"""Run the frozen three-build RAM timing protocol on a private guest overlay."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from represent import SCRIPTS, command, read, require, sha, write

ROOT = SCRIPTS.parent
LAB = ROOT / "实验环境/openeuler-x86_64/lab.py"
sys.path.insert(0, str(ROOT / "src"))
from kconc.artifacts import notes_id
from kconc.bma400_performance import summarize


def provision_overlay(root, out, bundle, key, run, create_account):
    spec = importlib.util.spec_from_file_location("teacher_init_archive", SCRIPTS/"iio-path/capture.py")
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    files = {"init":bundle/"session-init", "payload/session.pub":key.with_suffix(".pub")}
    if create_account:
        files["payload/provision-account.sh"] = bundle/"provision-account.sh"
    archive.archive(root/"provision.gz", files)
    overlay = root/"images/experiment.qcow2"
    run("provision", ["qemu-system-x86_64","-accel","kvm","-cpu","host","-smp","1","-m","768","-no-reboot",
        "-nodefaults","-monitor","none","-display","none","-serial","file:"+str(out/"provision.serial.log"),
        "-kernel",bundle/"original","-initrd",root/"provision.gz","-append","console=ttyS0 panic=-1 loglevel=4",
        "-drive","file="+str(overlay)+",format=qcow2,if=virtio"])
    serial = (out/"provision.serial.log").read_text(errors="replace")
    require("TEACHER_SESSION_KEY_INSTALLED" in serial, "could not set the temporary lab account key in the new overlay")
    if create_account:
        require("TEACHER_NEW_ACCOUNT_PREPARED" in serial, "could not verify the fresh guest account")
    write(out/"provision.json", {"passed":True,"kind":"offline overlay preparation","counted_as_formal":False,
                                "guest_public_key_sha256":sha(key.with_suffix(".pub"))})


def prepare(root, disk, out, bundle, binding):
    for d in ("images", "seed", "keys"):
        (root / d).mkdir()
    def run(name, argv):
        require(command(out, name, argv, timeout=120) == 0, name + " failed")
    run("overlay", ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", disk, root / "images/experiment.qcow2"])
    key = root / "keys/id_ed25519"
    run("session-key", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    identity = str(uuid.uuid4())
    (root / "seed/meta-data").write_text("instance-id: " + identity + "\nlocal-hostname: kconc-teacher\n")
    public = key.with_suffix(".pub").read_text().strip()
    provision = binding.get("overlay_provision", "historical-account")
    require(provision in ("official-fresh-account", "historical-account"), "unknown guest provisioning profile")
    provision_overlay(root, out, bundle, key, run, provision == "official-fresh-account")
    cloud = {"disable_root":True,"ssh_pwauth":False,
             "users":[{"name":"lab","shell":"/bin/bash","groups":["wheel"], "sudo":"ALL=(ALL) NOPASSWD:ALL",
                       "lock_passwd":True, "ssh_authorized_keys":[public]}],
             "write_files":[{"path":"/run/teacher-session.pub","content":public+"\n","permissions":"0644"}],
             "runcmd":[["install","-d","-m","0700","-o","lab","-g","lab","/home/lab/.ssh"],
                       ["install","-m","0600","-o","lab","-g","lab","/run/teacher-session.pub","/home/lab/.ssh/authorized_keys"],
                       ["restorecon","-RF","/home/lab/.ssh"]]}
    (root / "seed/user-data").write_text("#cloud-config\n" + json.dumps(cloud) + "\n")
    run("local-seed", ["cloud-localds", root / "seed/seed.img",root / "seed/user-data",root / "seed/meta-data"])


def affinity(ctrl, out, pin):
    cpus = sorted(os.sched_getaffinity(0))
    workers = sorted(ctrl.qmp("query-cpus-fast"),key=lambda v:v["cpu-index"])
    require(len(cpus)>=4 and [x["cpu-index"] for x in workers]==list(range(4)), "need four distinct available host CPUs")
    values=[]
    for i, worker in enumerate(workers):
        tid=worker["thread-id"]
        if pin:
            os.sched_setaffinity(tid,{cpus[i]})
        observed = sorted(os.sched_getaffinity(tid))
        require(observed == [cpus[i]], "vCPU affinity drifted")
        values.append({"vcpu":i,"host_tid":tid,"pinned_cpu":cpus[i]})
    require(ctrl.qmp("query-kvm")["enabled"], "guest does not use KVM")
    write(out / ("affinity-before.json" if pin else "affinity-after.json"), values)


def quiet_host(folder):
    samples=[]
    for turn in range(6):
        processes=[]
        for f in Path("/proc").glob("[0-9]*/comm"):
            try:
                name=f.read_text().strip()
                if not name.startswith("qemu-system") and name not in {"clang","clang-23","ld.lld","coqc","coqchk"}:
                    continue
                state=(f.parent/"stat").read_text().rsplit(")",1)[-1].split()[0]
            except (OSError,IndexError):
                continue
            processes.append({"pid":int(f.parent.name),"name":name,"state":state})
        samples.append(processes)
        # The kernel can retain the comm of a powered-off VM until its
        # parent reaps it. A zombie no longer executes or takes CPU time.
        if all(p["state"] in ("Z","X") for p in processes):
            write(folder/"quiet-host.json",{"passed":True,"samples":samples})
            return
        if turn<5:
            time.sleep(1)
    write(folder/"quiet-host.json",{"passed":False,"samples":samples})
    raise ValueError("another build, proof check or VM is active; see quiet-host.json")


def checked_slot(a, binding, root, ctrl, port, slot, boots):
    arm=slot["variant"]
    record=binding["arms"][arm]
    formal=slot["phase"]=="formal"
    folder=a.output / slot["directory"]
    folder.mkdir()
    target=a.bundle / arm
    n, warm, reps=(20000,2,4) if formal else (16,0,1)
    params=["root=/dev/vda2","rw","console=ttyS0",f"kconc.c07={folder.name}:{record['build_id']}","kconc_bma400.c07=1",
            f"kconc_bma400.calls={n}",f"kconc_bma400.warmups={warm}",f"kconc_bma400.samples={reps}"]
    os.environ.update(LAB_KERNEL=str(target),LAB_APPEND=" ".join(params))
    helpers = [SCRIPTS / n for n in ("c07-bma400-guest.py","c02-bench-guest.py","c02-bulk-guest.py")]
    opts = ["-i",str(root/"keys/id_ed25519"),"-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o",
            "ConnectTimeout=3","-o","StrictHostKeyChecking=accept-new","-o","UserKnownHostsFile="+str(root/"keys/known_hosts")]
    ssh=["ssh",*opts,"-p",str(port),"lab@127.0.0.1"]
    def run(label, argv, timeout=120):
        code=command(folder,label,argv,separate_stderr=True,timeout=timeout)
        require(code==0, f"{label} returned {code}, see {folder.name}/{label}.log")
    def guest(action):
        run(action,[*ssh,"sudo","-n","taskset","-c","2","python3","-B","teacher/"+helpers[0].name,action])
        data=read(folder/(action+".log"))
        require(data.get("passed"),action+" failed")
        return data
    quiet_host(folder)
    data=[]
    try:
        run("start",[sys.executable,"-B",LAB,"start"])
        affinity(ctrl,folder,True)
        for attempt in range(45):
            if command(folder,f"connect-{attempt+1:02d}",[*ssh,"true"],timeout=9)==0:
                break
            time.sleep(2)
        else:
            raise RuntimeError("guest SSH did not become ready; see serial and connection logs")
        run("mkdir",[*ssh,"mkdir","-p","teacher"])
        run("install-helpers",["scp",*opts,"-P",str(port),*helpers,"lab@127.0.0.1:teacher/"])
        run("guest-sha256",[*ssh,"sha256sum",*["teacher/"+h.name for h in helpers]])
        actual=(folder/"guest-sha256.log").read_text().splitlines()
        require(actual==[sha(h)+"  teacher/"+h.name for h in helpers], "guest helper hash differs")
        prepared=guest("prepare")
        inv=prepared["inventory"]
        boot=str(uuid.UUID(prepared["boot_id"]))
        slot["boot_id"]=boot
        require(boot not in boots,"boot ID reused")
        boots.add(boot)
        launch=read(root/"evidence/last-launch.json")
        actual=launch["kernel_artifact"]
        checks={"build":notes_id(base64.b64decode(inv["notes"],validate=True))==record["build_id"],
                "config":inv["config_sha256"]==record["config_sha256"],"release":inv["release"]==record["release"],
                "distribution":"openEuler 24.03 (LTS-SP3)" in prepared["os_release"],"cpu":inv["cpu_online"]=="0-3",
                "root":prepared["root_mount"].split()[2]==prepared["vda2"],"kernel":
                actual["sha256_before_launch"]==actual["sha256_after_launch"]==binding["materials"][arm],
                "cmdline":inv["cmdline"].split()==params,"direct_boot":"-initrd" not in launch["command"]}
        write(folder/"identity.json",{"boot_id":boot,"checks":checks,"kernel_build_id":record["build_id"]})
        require(all(checks.values()),"loaded guest identity differs")
        if formal:
            data=guest("time")["results"]["rows"]
        else:
            guest("check")
            diag=guest("profile")
            require(diag["bulk_calls"]==16 and diag["noop_calls"]==(0 if arm=="skip-noop" else 96),"unexpected empty-callback count")
            slot["empty_callbacks"]=diag["noop_calls"]
        affinity(ctrl,folder,False)
    finally:
        code=1
        try:
            if ctrl.process_alive():
                code=command(folder,"stop",[sys.executable,"-B",LAB,"stop"],timeout=100)
        finally:
            if ctrl.process_alive():
                pid=int((ctrl.RUN/"qemu.pid").read_text().strip())
                # Only this run's process owns the unique QMP socket. A forced
                # stop remains a failed slot, even if every timed row exists.
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    if not ctrl.process_alive():
                        break
                    os.kill(pid, sig)
                    for _ in range(25):
                        if not ctrl.process_alive():
                            break
                        time.sleep(.1)
                write(folder/"forced-cleanup.json",{"pid":pid,"still_running":ctrl.process_alive()})
                code=1
        for name in ("serial.log","last-launch.json","last-stop.json"):
            source=root/("logs" if name=="serial.log" else "evidence")/name
            if source.is_file():
                shutil.copyfile(source,folder/name)
        require(code==0 and (folder/"last-stop.json").is_file(),"missing clean shutdown")
        stop=read(folder/"last-stop.json")
        require(all(stop.get(k) for k in ("graceful_stop_observed","process_exit_observed","qmp_shutdown_confirmed"))
                and stop["qmp_shutdown_event"]["data"]["guest"],"missing guest-initiated clean shutdown")
    return data


def measure(a, binding, result):
    protocol=read(a.bundle/"protocol.json")
    plans=protocol["boot_orders"]
    arms=protocol["variants"]
    slots=[{"directory":"check-"+arm,"phase":"functional","variant":arm,"status":"not_started"} for arm in arms]
    if a.case=="opt-ram":
        slots.extend({"directory":f"r{i:02d}-{arm}","round":i,"phase":"formal","variant":arm,"status":"not_started"}
                     for i,order in enumerate(plans,1) for arm in order)
    result.update(slots=slots)
    write(a.output/"plan.json",{"slots":slots,"protocol_sha256":sha(a.bundle/"protocol.json"),"disk_sha256":binding["disk_sha256"],
            "arms":binding["arms"],"formal_replacement":False})
    for tool in ("qemu-system-x86_64","qemu-img","cloud-localds","ssh-keygen","ssh","scp"):
        require(shutil.which(tool),"missing Linux dependency: "+tool)
    rows=[]
    boots=set()
    with tempfile.TemporaryDirectory(prefix="kconc-ram-") as td:
        root=Path(td)
        prepare(root,a.disk,a.output,a.bundle,binding)
        with socket.socket() as s:
            s.bind(("127.0.0.1",0))
            port=s.getsockname()[1]
        for k in tuple(os.environ):
            if k.startswith("LAB_"):
                del os.environ[k]
        os.environ.update(LAB_DIR=str(root),LAB_SSH_PORT=str(port),LAB_MEMORY_MIB="4096",LAB_VSOCK_CID=str(port))
        spec=importlib.util.spec_from_file_location("teacher_qemu_lab",LAB)
        ctrl=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ctrl)
        for slot in slots:
            slot["status"]="started"
            result["attempted"]+=1
            write(a.output/"result.json",result)
            try:
                data=checked_slot(a,binding,root,ctrl,port,slot,boots)
            except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
                slot.update(status="failed",diagnostic=str(exc))
                break
            slot["status"]="passed"
            for row in data:
                rows.append({"round":slot["round"],"variant":slot["variant"],"phase":"warmup" if row["warmup"] else "measured",
                             "batch":row["sample"]+1,"calls":row["cycles"],"elapsed_ns":row["elapsed_ns"]})
    result["preparation_boots"]=int((a.output/"provision.json").is_file())
    result["observed_guest_boot_ids"]=sorted(boots)
    if a.case=="quick-opt":
        result.update(passed=all(s["status"]=="passed" for s in slots),
                      empty_callbacks={s["variant"]:s["empty_callbacks"] for s in slots if "empty_callbacks" in s},
                      measured_batches=0)
        return
    stats=summarize(rows,plans)
    write(a.output/"timing-rows.json",rows)
    write(a.output/"statistics.json",stats)
    result.update(complete_rounds=stats["complete_rounds"],actual_pairs=stats["inference_pairs_per_comparison"],
                  value_gate_passed=stats["value_gate_passed"],statistics="statistics.json",
                  passed=all(s["status"]=="passed" for s in slots) and stats["eligible"])
