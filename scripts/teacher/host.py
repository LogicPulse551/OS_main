"""Check host requirements for the chosen operation before acquiring its materials."""
import os
import platform
import shutil
import subprocess
import sys


def preflight(case, vm, install=False, offline=False):
    if sys.version_info < (3, 11):
        raise ValueError("本机复现需要 Python 3.11 或更新版本。")
    if platform.system() != "Linux" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("内核实跑与证书复算支持 x86_64 Linux。")
    commands = {}
    if vm:
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise ValueError("当前用户需要能读写 /dev/kvm。请在主机启用虚拟化并授予当前账户 KVM 访问权限。")
        commands.update({"qemu-system-x86_64":"qemu-system-x86", "qemu-img":"qemu-utils"})
    if case in ("opt-ram", "quick-opt"):
        if not os.access("/dev/vhost-vsock", os.R_OK | os.W_OK):
            raise ValueError("性能实验需要当前用户能读写 /dev/vhost-vsock。")
        commands.update({"cloud-localds":"cloud-image-utils", "ssh-keygen":"openssh-client",
                         "ssh":"openssh-client", "scp":"openssh-client"})
    if case == "opt-proof":
        commands["gcc"] = "gcc"
    packages = sorted({package for cmd,package in commands.items() if not shutil.which(cmd)})
    if not packages:
        return
    names = " ".join(packages)
    if offline or not shutil.which("apt-get"):
        raise ValueError("当前功能需要主机软件包 " + names)
    if not install and sys.stdin.isatty():
        install = input(f"此功能需要 {names}。允许通过系统包管理器安装并继续？[Y/n] ").strip().lower() in ("", "y", "yes")
    if not install:
        raise ValueError("缺少主机软件包 " + names + "。可在终端重新运行入口并允许安装，或加 --install-deps。")
    command = [] if os.geteuid() == 0 else ["sudo"]
    if command and not shutil.which("sudo"):
        raise ValueError("安装主机依赖需要管理员权限。")
    for args in (["update"], ["install", "-y", "--no-install-recommends", *packages]):
        subprocess.run([*command, "apt-get", *args], check=True)
    missing = [cmd for cmd in commands if not shutil.which(cmd)]
    if missing:
        raise ValueError("安装后仍缺少命令 " + ", ".join(missing))
