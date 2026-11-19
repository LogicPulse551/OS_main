#!/usr/bin/env python3
"""Isolated original SEQ reproduction; reuse the accepted command recorder."""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,shlex,shutil,sys,tarfile
HERE=pathlib.Path(__file__).resolve();REPO=HERE.parents[2]
spec=importlib.util.spec_from_file_location('b02_recording',HERE.with_name('b02.py'))
recording=importlib.util.module_from_spec(spec);spec.loader.exec_module(recording)
digest=recording.digest;write_json=recording.write_json
class Runner(recording.Runner):
    def __init__(self,root,evidence):
        super().__init__(root,evidence)
        self.env['OPAMSWITCH']='seq'
        self.runner_source=HERE.read_bytes()
        self.lock=json.loads((REPO/'configs/optimization/seq.lock.json').read_text(encoding='utf-8'))
    def bootstrap(self,base):
        if (self.root/'opam-root').exists() or (self.root/'bin').exists():raise ValueError('Do not overwrite existing environment')
        opam=base/'bin/opam'
        if digest(opam)!=self.lock['opam_binary_sha256']:raise ValueError('opam identity mismatch')
        (self.root/'bin').mkdir();shutil.copyfile(opam,self.root/'bin/opam');(self.root/'bin/opam').chmod(0o755)
        shutil.copytree(base/'deps',self.root/'deps',symlinks=True)
        write_json(self.root/'bootstrap-provenance.json',dict(base=str(base),opam_sha256=digest(opam),recorder_sha256=digest(HERE.with_name('b02.py')),dependency_files={p.relative_to(base/'deps').as_posix():digest(p) for p in (base/'deps').rglob('*') if p.is_file()}))
        shutil.copyfile(HERE.with_name('b02.py'),self.root/'b02-recorder.py')
        self.run('opam-init',['opam','init','--bare','--no-setup','--disable-sandboxing','-y','default','https://opam.ocaml.org'])
    def compiler(self):self.run('ocaml-switch',['opam','switch','create','seq','ocaml-base-compiler.4.14.2','-y','--jobs=2'])
    def coq(self):
        proof_packages={'coq-paco','coq-itree',*self.lock['dependency_pins']}
        packages=[n+'.'+v for n,v in self.lock['installed_packages'].items() if n not in proof_packages]
        self.run('coq-install',['opam','install',*(packages or ['coq.8.15.0']),'-y','--jobs=2','--assume-depexts'])
    def dependencies(self):
        dest=self.root/'pinned-dependencies';dest.mkdir(exist_ok=False)
        self.run('coq-repository',['opam','repository','add','coq-released','https://coq.inria.fr/opam/released','-y'])
        for name,pin in self.lock['dependency_pins'].items():
            storage=pin.get('storage_name',name)
            archive=dest/(storage+'.tar.gz')
            self.run('download-'+name,['curl','-fL','--retry','2','-o',str(archive),pin['url']])
            if digest(archive)!=pin['archive_sha256']:raise ValueError('Dependency archive mismatch: '+name)
            metadata=pin['metadata'].encode()
            if hashlib.sha256(metadata).hexdigest()!=pin['metadata_sha256']:raise ValueError('Dependency metadata mismatch: '+name)
            unpack=dest/storage
            with tarfile.open(archive) as tf:tf.extractall(unpack,filter='data')
            children=list(unpack.iterdir())
            if len(children)!=1 or not children[0].is_dir():raise ValueError('Unexpected dependency tree')
            tree=children[0]
            # Opam prefers a package-named recipe when present. Verify that
            # it matches the locked effective recipe, not just its version.
            named=tree/(name+'.opam')
            if named.exists() and digest(named)!=pin['metadata_sha256']:raise ValueError('Named dependency recipe mismatch: '+name)
            # Keep upstream files untouched; a root recipe supports packages
            # (sflib/promising-lib) that do not supply a named recipe.
            recipe=tree/'opam'
            if recipe.exists():raise ValueError('Refuse to overwrite upstream recipe')
            recipe.write_bytes(metadata)
            write_json(unpack/'provenance.json',pin)
            self.run('pin-'+name,['opam','pin','add','--no-action','--kind=path',name+'.'+pin['version'],str(tree),'-y'])
        self.install_dependencies()
    def install_dependencies(self):
        pins=[name+'.'+pin['version'] for name,pin in self.lock['dependency_pins'].items()]
        self.run('proof-dependencies',['opam','install','coq.8.15.0','coq-paco.4.1.2','coq-itree.4.0.0',*pins,'-y','--jobs=2','--assume-depexts'])
    def source(self,tree):
        for n,h in self.lock['source_files'].items():
            path=pathlib.PurePosixPath(n)
            if path.is_absolute() or '..' in path.parts:raise ValueError('Unsafe source path')
            if digest(tree/n)!=h:raise ValueError('Source identity mismatch: '+n)
        work=self.root/'source-01';work.mkdir(exist_ok=False)
        for n in self.lock['source_files']:
            target=work/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(tree/n,target)
        write_json(self.root/'source-copy.json',dict(source_tree=str(tree),work=str(work),files=self.lock['source_files'],compiled_files_copied=0))
    def flags(self):
        work=self.root/'source-01';flags=[]
        for line in (work/'_CoqProject').read_text().splitlines():
            fs=shlex.split(line)
            if fs and fs[0] in ['-R','-Q']:
                if len(fs)!=3:raise ValueError('Unexpected load path')
                flags += [fs[0],str(work/fs[1]),fs[2]]
        if not flags:raise ValueError('Missing load paths')
        return flags
    def verify_versions(self):
        if not self.lock['installed_packages']:raise ValueError('Missing installed package lock')
        attempt=self.run('toolchain-check',['opam','list','--installed','--columns=name,version','--color=never'])
        actual={}
        for line in (attempt/'stdout.log').read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            name,version=line.split();actual[name]=version
        expected=self.lock['installed_packages']
        write_json(attempt/'version-check.json',dict(expected=expected,actual=actual,passed=actual==expected))
        if actual!=expected:raise ValueError('Toolchain package versions do not match lock')
        # A package named dev alone is not an identity check.
        for name,pin in self.lock['dependency_pins'].items():
            if digest(self.root/'pinned-dependencies'/(pin.get('storage_name',name)+'.tar.gz'))!=pin['archive_sha256']:raise ValueError('Dependency archive identity mismatch')
            folder=self.root/'pinned-dependencies'/pin.get('storage_name',name)
            trees=[p for p in folder.iterdir() if p.is_dir()]
            if len(trees)!=1 or digest(trees[0]/pin.get('effective_recipe','opam'))!=pin['metadata_sha256']:raise ValueError('Effective dependency recipe identity mismatch')
    def verify_source(self):
        for name,expected in self.lock['source_files'].items():
            if digest(self.root/'source-01'/name)!=expected:raise ValueError('Source identity mismatch: '+name)
    def snapshot(self):
        self.verify_versions()
        work=self.root/('toolchain-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
        work.mkdir(exist_ok=False)
        self.run('switch-export',['opam','switch','export','--full',str(work/'switch.export')])
        for name,version in self.lock['installed_packages'].items():
            log=self.run('metadata-'+name,['opam','show','--raw',name+'.'+version])
            shutil.copyfile(log/'stdout.log',work/(name+'.opam'))
        files={}
        for dirname in ['opam-root/seq/lib/coq','opam-root/seq/bin']:
            for path in (self.root/dirname).rglob('*'):
                if path.is_file():files[path.relative_to(self.root).as_posix()]=digest(path)
        write_json(self.root/'toolchain-identity.json',dict(installed_files=files,packages=self.lock['installed_packages'],opam_binary_sha256=digest(self.root/'bin/opam')))
    def verify_runtime(self):
        baseline=json.loads((self.root/'toolchain-identity.json').read_text())
        if baseline['packages']!=self.lock['installed_packages']:raise ValueError('Runtime package identity mismatch')
        if digest(self.root/'bin/opam')!=self.lock['opam_binary_sha256']:raise ValueError('opam identity mismatch')
        for name,expected in baseline['installed_files'].items():
            if digest(self.root/name)!=expected:raise ValueError('Installed proof toolchain changed: '+name)
    def build(self):
        self.verify_versions();self.verify_source()
        self.verify_runtime()
        self.run('seq-build',['opam','exec','--','make','build','-j2'],self.root/'source-01')
    def check(self):
        self.verify_versions();self.verify_source()
        self.verify_runtime()
        self.run('coqchk-upstream',['opam','exec','--','coqchk',*self.flags(),'PromisingSEQ.OptimizerAdequacy'])
    def examples(self):
        self.verify_versions();self.verify_source()
        self.verify_runtime()
        work=self.root/('examples-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
        work.mkdir(exist_ok=False)
        for name in ['Cases.v','Reproduce.v','RejectWrongOutput.v','RejectMissingPremises.v']:
            shutil.copyfile(REPO/'proofs/seq'/name,work/name)
        flags=[*self.flags(),'-R',str(work),'O03']
        for name in ['Cases.v','Reproduce.v']:
            self.run('coqc-'+name,['timeout','300','opam','exec','--','coqc','-time',*flags,name],work)
        for name,diagnostic in [('RejectWrongOutput.v','Unable to unify'),('RejectMissingPremises.v','Attempt to save an incomplete proof')]:
            attempt=self.run('reject-'+name,['timeout','60','opam','exec','--','coqc',*flags,name],work,expected_exit=1)
            if diagnostic not in (attempt/'stderr.log').read_text():raise ValueError('Unexpected rejection reason: '+name)
        self.run('coqchk-examples',['opam','exec','--','coqchk',*flags,'O03.Cases','O03.Reproduce'],work)
        outputs={}
        for name in ['rr','wr','dse']:
            if 'Closed under the global context' not in (work/('assumptions-output-'+name+'.out')).read_text():raise ValueError('Unexpected output equality axiom')
            before=(work/('input-'+name+'.out')).read_text();after=(work/('output-'+name+'.out')).read_text()
            if before==after:raise ValueError('Missing actual transformation: '+name)
            outputs[name]=dict(input=before,output=after,output_equality_checked=True,unconditional_source_safety=False)
        write_json(work/'completed.json',dict(outputs=outputs,boundary_equalities=9,changed_inequalities=3,original_model_instances=3,expected_rejections=2,kernel_adapted=False,source_premises_established=False,method='Coq computation, equality proofs and full coqchk; no extracted optimizer runtime'))
        print('EXAMPLES',str(work),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,required=True);p.add_argument('--evidence',type=pathlib.Path,required=True)
    p.add_argument('--base-env',type=pathlib.Path);p.add_argument('--source-tree',type=pathlib.Path)
    p.add_argument('stage',choices=['bootstrap','compiler','coq','dependencies','install_dependencies','source','snapshot','build','check','examples','command']);p.add_argument('command',nargs=argparse.REMAINDER)
    a=p.parse_args()
    if os.name!='posix':p.error('Run inside WSL Debian')
    for target in [a.root.resolve(),a.evidence.resolve()]:
        if target==REPO or REPO in target.parents:p.error('Runtime and evidence must be outside repository')
    r=Runner(a.root,a.evidence)
    if a.stage=='bootstrap':
        if not a.base_env:p.error('--base-env required')
        r.bootstrap(a.base_env.resolve())
    elif a.stage=='source':
        if not a.source_tree:p.error('--source-tree required')
        r.source(a.source_tree.resolve())
    elif a.stage=='command':
        if not a.command:p.error('command required')
        r.run('command',a.command)
    else:getattr(r,a.stage)()
if __name__=='__main__':main()
