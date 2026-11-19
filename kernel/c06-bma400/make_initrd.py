"""Build a small initramfs with a static diagnostic reader and no replacement /init."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def archive(binary):
    out=bytearray()
    entries=[("c06-debug",0o040755,b""),("c06-read",0o100755,binary),("TRAILER!!!",0,b"")]
    for ino,(name,mode,data) in enumerate(entries,1):
        tag=name.encode()+b"\0"
        fields=[ino,mode,0,0,2 if mode==0o040755 else 1,0,len(data),0,0,0,0,len(tag),0]
        out.extend(b"070701"+"".join(f"{v:08x}" for v in fields).encode()+tag)
        out.extend(b"\0"*(-len(out)%4));out.extend(data);out.extend(b"\0"*(-len(out)%4))
    out.extend(b"\0"*(-len(out)%512))
    return out


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    out=parser.parse_args().output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).with_name("read-live.c")
    argv=["gcc","-static","-Os","-Wall","-Werror","-s",str(source),"-o",str(out/"c06-read")]
    p=subprocess.run(argv,capture_output=True)
    (out/"stdout").write_bytes(p.stdout);(out/"stderr").write_bytes(p.stderr)
    (out/"command.json").write_text(json.dumps(dict(argv=argv,rc=p.returncode),indent=2)+"\n")
    p.check_returncode()
    initrd=out/"observer.cpio"
    initrd.write_bytes(archive((out/"c06-read").read_bytes()))
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    (out/"result.json").write_text(json.dumps(dict(path=str(initrd),sha256=sha(initrd),size=initrd.stat().st_size,
        source_sha256=sha(source),binary_sha256=sha(out/"c06-read")),indent=2)+"\n")
