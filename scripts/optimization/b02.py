#!/usr/bin/env python3
"""Isolated B02 reproduction steps; every command keeps its own attempt log.

Only our runner is distributed. Upstream B02 and toolchain sources stay outside
the repository. No step modifies a kernel, VM, global opam switch or shell rc.
"""
import argparse, datetime, hashlib, json, os, pathlib, shutil, subprocess, sys, shlex

REPO=pathlib.Path(__file__).resolve().parents[2]

def digest(path):
    h=hashlib.sha256()
    with pathlib.Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def write_json(path,data):
    with path.open('x',encoding='utf-8') as f:json.dump(data,f,ensure_ascii=False,indent=2)

class Runner:
    def __init__(self,root,evidence):
        self.root=root.resolve(); self.evidence=evidence.resolve()
        self.runner_source=pathlib.Path(__file__).read_bytes()
        self.root.mkdir(parents=True,exist_ok=True);self.evidence.mkdir(parents=True,exist_ok=True)
        self.env=os.environ.copy()
        self.env.update(OPAMROOT=str(self.root/'opam-root'),OPAMYES='1',OPAMJOBS='2',OPAMSWITCH='b02',
                        OPAMNOENVNOTICE='1',PATH=str(self.root/'bin')+os.pathsep+self.env['PATH'])
        deps=self.root/'deps/usr'
        if deps.exists():
            for key,path in [('CPATH',deps/'include/x86_64-linux-gnu'),('LIBRARY_PATH',deps/'lib/x86_64-linux-gnu'),('LD_LIBRARY_PATH',deps/'lib/x86_64-linux-gnu')]:
                self.env[key]=str(path)+(os.pathsep+self.env[key] if self.env.get(key) else '')
    def run(self,label,cmd,cwd=None,env=None,expected_exit=0):
        attempt=self.evidence/(label+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
        attempt.mkdir(exist_ok=False)
        (attempt/'runner.py').write_bytes(self.runner_source)
        record=dict(command=cmd,cwd=str(cwd or self.root),started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    runner_sha256=hashlib.sha256(self.runner_source).hexdigest(),expected_exit=expected_exit,environment={k:self.env[k] for k in ['OPAMROOT','OPAMSWITCH','OPAMJOBS']})
        write_json(attempt/'invocation.json',record)
        print('RUN',label,str(attempt),flush=True)
        try:
            with (attempt/'stdout.log').open('wb') as out,(attempt/'stderr.log').open('wb') as err:
                p=subprocess.run(cmd,cwd=cwd or self.root,env=env or self.env,stdout=out,stderr=err)
        except BaseException as error:
            record.update(exit_code=None,error=repr(error),expected_exit_matched=False,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            write_json(attempt/'result.json',record)
            raise
        record.update(exit_code=p.returncode,expected_exit_matched=p.returncode==expected_exit,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        write_json(attempt/'result.json',record)
        print('EXIT',label,p.returncode,flush=True)
        if p.returncode!=expected_exit:raise SystemExit(p.returncode or 1)
        return attempt
    def bootstrap(self):
        (self.root/'bin').mkdir(exist_ok=True)
        opam=self.root/'bin/opam'
        if opam.exists():raise SystemExit('Existing opam binary: resume using a later stage; never overwrite.')
        self.run('download-opam',['curl','-fL','--retry','2','-o',str(opam),'https://github.com/ocaml/opam/releases/download/2.2.1/opam-2.2.1-x86_64-linux'])
        opam.chmod(0o755)
        write_json(self.root/'opam-download.json',dict(url='https://github.com/ocaml/opam/releases/download/2.2.1/opam-2.2.1-x86_64-linux',sha256=digest(opam)))
        self.run('opam-version',[str(opam),'--version'])
        self.run('opam-init',[str(opam),'init','--bare','--no-setup','--disable-sandboxing','-y','default','https://opam.ocaml.org'])
    def compiler(self):
        self.run('ocaml-switch',['opam','switch','create','b02','ocaml-base-compiler.4.12.1','-y','--jobs=2'])
    def coq(self):
        self.run('coq-install',['opam','install','coq.8.13.1','-y','--jobs=2','--assume-depexts'])
    def local_deps(self):
        dest=self.root/'deps'
        dest.mkdir(exist_ok=False)
        records=[]
        for pattern in ['libgmp10_*.deb','libgmp-dev_*.deb']:
            packages=list(self.root.glob(pattern))
            if len(packages)!=1:raise SystemExit('Expected one downloaded Debian package: '+pattern)
            package=packages[0]
            self.run('extract-'+package.name,['dpkg-deb','-x',str(package),str(dest)])
            records.append(dict(path=str(package),sha256=digest(package)))
        write_json(self.root/'local-deps.json',records)
    def paco(self):
        self.run('coq-repository',['opam','repository','add','coq-released','https://coq.inria.fr/opam/released','-y'])
        self.run('paco-install',['opam','install','coq.8.13.1','coq-paco.4.0.4','-y','--jobs=2','--assume-depexts'])
    def source(self,source_tree):
        lock=json.loads((REPO/'configs/optimization/b02.lock.json').read_text(encoding='utf-8'))
        # Check the entire selected tree BEFORE creating a new build directory.
        for name,expected in lock['source_files'].items():
            path=pathlib.PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:raise ValueError('Unsafe source path')
            if digest(source_tree/name)!=expected:raise ValueError('Source identity mismatch: '+name)
        work=self.root/'source-01';work.mkdir(exist_ok=False)
        for name in lock['source_files']:
            target=work/name;target.parent.mkdir(exist_ok=True,parents=True)
            shutil.copyfile(source_tree/name,target)
        write_json(self.root/'source-copy.json',dict(source_tree=str(source_tree),work=str(work),files=lock['source_files'],compiled_files_copied=0))
        print('SOURCE',len(lock['source_files']),'verified files',flush=True)
    def build(self):
        self.verify_versions()
        self.run('b02-build',['opam','exec','--','make','build','-j2'],self.root/'source-01')
    def verify_versions(self):
        expected=json.loads((REPO/'configs/optimization/b02.lock.json').read_text(encoding='utf-8'))['installed_packages']
        attempt=self.run('toolchain-check',['opam','list','--installed','--columns=name,version','--color=never'])
        actual={}
        for line in (attempt/'stdout.log').read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            name,version=line.split();actual[name]=version
        write_json(attempt/'version-check.json',dict(expected=expected,actual=actual,passed=actual==expected))
        if actual!=expected:raise SystemExit('Toolchain package versions do not match lock')
    def flags(self):
        work=self.root/'source-01';flags=[]
        for line in (work/'_CoqProject').read_text().splitlines():
            fields=shlex.split(line)
            if fields and fields[0] in ['-R','-Q']:
                if len(fields)!=3:raise ValueError('Unexpected Coq load path')
                flags += [fields[0],str(work/fields[1]),fields[2]]
        if not flags:raise ValueError('No artifact load paths')
        return flags
    def check(self):
        self.run('coqchk-upstream',['opam','exec','--','coqchk',*self.flags(),'CompOptCert.VerifiedOpt'])
    def examples(self):
        self.verify_versions()
        work=self.root/('examples-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
        work.mkdir(exist_ok=False)
        for name in ['Cases.v','Evaluation.v','Reproduce.v','Extract.v','main.ml','check_output.py','RejectWrongOutput.v','RejectMissingPremises.v']:
            shutil.copyfile(REPO/'proofs/b02'/name,work/name)
        for name in ['Cases.v','Evaluation.v','Extract.v']:
            self.run('coqc-'+name,['timeout','180','opam','exec','--','coqc','-time',*self.flags(),'-R',str(work),'O02',name],work)
        # Standard Coq 8.13.1 extraction support, kept outside the repository.
        big=self.root/'opam-root/b02/.opam-switch/sources/coq.8.13.1/plugins/extraction/big.ml'
        shutil.copyfile(big,work/'big.ml')
        self.run('compile-extracted',['opam','exec','--','ocamlfind','ocamlopt','-package','zarith','-linkpkg','big.ml','original.mli','original.ml','main.ml','-o','run-original'],work)
        attempt=self.run('run-extracted',['timeout','120',str(work/'run-original')],work)
        shutil.copyfile(attempt/'stdout.log',work/'outputs.jsonl')
        self.run('check-outputs',[sys.executable,'-B','check_output.py','outputs.jsonl'],work)
        self.run('coqc-Reproduce.v',['timeout','180','opam','exec','--','coqc','-time',*self.flags(),'-R',str(work),'O02','Reproduce.v'],work)
        self.run('coqchk-examples',['opam','exec','--','coqchk',*self.flags(),'-R',str(work),'O02','O02.Reproduce'],work)
        for name,diagnostic in [('RejectWrongOutput.v','Unable to unify'),('RejectMissingPremises.v','while it is expected to have type')]:
            attempt=self.run('reject-'+name,['opam','exec','--','coqc',*self.flags(),'-R',str(work),'O02',name],work,expected_exit=1)
            if diagnostic not in (attempt/'stderr.log').read_text():
                raise RuntimeError('Unexpected rejection reason: '+str(attempt))
        write_json(work/'completed.json',dict(proofs_checked=True,algorithms_executed=4,boundary_cases=5,coq_output_equalities=['cp'],extraction_runtime_trusted=True,source_premises_established=False,kernel_adapted=False))
    def snapshot(self):
        dest=self.root/('toolchain-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
        dest.mkdir(exist_ok=False)
        for label,cmd in [('coq-version',['opam','exec','--','coqc','--version']),('ocaml-version',['opam','exec','--','ocamlc','-version']),('installed-packages',['opam','list','--installed','--columns=name,version','--color=never']),('switch-export',['opam','switch','export',str(dest/'switch.export'),'--full'])]:
            self.run(label,cmd)
        packages=self.root/'opam-root/b02/.opam-switch/packages'
        shutil.copytree(packages,dest/'packages')
        files={p.relative_to(dest).as_posix():digest(p) for p in dest.rglob('*') if p.is_file()}
        write_json(dest/'manifest.json',dict(files=files,opam_binary_sha256=digest(self.root/'bin/opam'),local_deps=json.loads((self.root/'local-deps.json').read_text())))
    def command(self,cmd):
        self.run('command',cmd)

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,required=True);p.add_argument('--evidence',type=pathlib.Path,required=True)
    p.add_argument('--source-tree',type=pathlib.Path)
    p.add_argument('stage',choices=['bootstrap','compiler','coq','local-deps','paco','source','build','check','examples','snapshot','verify-versions','command']);p.add_argument('command',nargs=argparse.REMAINDER)
    a=p.parse_args()
    if os.name!='posix':p.error('Run inside WSL Debian')
    repo=pathlib.Path(__file__).resolve().parents[2]
    for dest in [a.root.resolve(),a.evidence.resolve()]:
        if dest==repo or repo in dest.parents:p.error('Build and evidence directories must be outside the repository')
    r=Runner(a.root,a.evidence)
    if a.stage=='command':
        if not a.command:p.error('command is required')
        r.command(a.command)
    elif a.stage=='source':
        if not a.source_tree:p.error('--source-tree is required')
        r.source(a.source_tree.resolve())
    else:getattr(r,a.stage.replace('-','_'))()
if __name__=='__main__':main()
