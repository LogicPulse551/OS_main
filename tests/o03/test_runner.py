"""SEQ isolation, source integrity, and dev dependency identity gates."""
import importlib.util,json,pathlib,tempfile,unittest,tarfile,shutil,hashlib
from unittest.mock import patch
REPO=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('seq_runner',REPO/'scripts/optimization/seq.py')
seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq)

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=pathlib.Path(self.temp.name)
        self.runner=seq.Runner(self.base/'env',self.base/'records')
        self.source=self.base/'source';self.source.mkdir()
        (self.source/'a.v').write_text('Check nat.\n')
        self.runner.lock={'source_files':{'a.v':seq.digest(self.source/'a.v')},'installed_packages':{'coq':'8.15.0'},'dependency_pins':{}}
    def versions(self,version):
        attempt=self.base/'version-attempt';attempt.mkdir()
        (attempt/'stdout.log').write_text('# Name Version\ncoq '+version+'\n')
        return patch.object(self.runner,'run',return_value=attempt)
    def test_isolated_switch_and_root(self):
        self.assertEqual(self.runner.env['OPAMSWITCH'],'seq')
        self.assertEqual(self.runner.env['OPAMROOT'],str(self.base/'env/opam-root'))
    def test_changed_source_rejected_before_copy(self):
        (self.source/'a.v').write_text('Axiom inconsistent : False.')
        with self.assertRaisesRegex(ValueError,'identity mismatch'):self.runner.source(self.source)
        self.assertFalse((self.runner.root/'source-01').exists())
    def test_compiled_files_not_copied_and_existing_work_not_overwritten(self):
        (self.source/'a.vo').write_bytes(b'old proof')
        self.runner.source(self.source)
        self.assertFalse((self.runner.root/'source-01/a.vo').exists())
        with self.assertRaises(FileExistsError):self.runner.source(self.source)
        self.runner.verify_source()
    def test_path_traversal_rejected(self):
        self.runner.lock['source_files']={'../a.v':'0'*64}
        with self.assertRaisesRegex(ValueError,'Unsafe source path'):self.runner.source(self.source)
    def test_matching_toolchain_and_changed_toolchain(self):
        with self.versions('8.15.1'),self.assertRaisesRegex(ValueError,'versions do not match'):self.runner.verify_versions()
        record=json.loads((self.base/'version-attempt/version-check.json').read_text())
        self.assertFalse(record['passed'])
    def test_dev_version_is_insufficient_without_source_identity(self):
        dest=self.runner.root/'pinned-dependencies';dest.mkdir()
        (dest/'coq-sflib.tar.gz').write_bytes(b'unexpected archive')
        self.runner.lock['dependency_pins']={'coq-sflib':{'archive_sha256':'0'*64}}
        with self.versions('8.15.0'),self.assertRaisesRegex(ValueError,'archive identity'):self.runner.verify_versions()
    def test_build_rejects_changed_original_before_launch(self):
        self.runner.source(self.source)
        (self.runner.root/'source-01/a.v').write_text('changed')
        with patch.object(self.runner,'verify_versions'),patch.object(self.runner,'run') as run,self.assertRaisesRegex(ValueError,'Source identity'):
            self.runner.build()
        run.assert_not_called()
    def test_bootstrap_preserves_existing_environment(self):
        (self.runner.root/'opam-root').mkdir()
        marker=self.runner.root/'opam-root/marker';marker.write_text('accepted baseline')
        with self.assertRaisesRegex(ValueError,'overwrite'):self.runner.bootstrap(self.base/'base')
        self.assertEqual(marker.read_text(),'accepted baseline')
    def test_installed_proof_object_tampering_is_rejected(self):
        opam=self.runner.root/'bin/opam';opam.parent.mkdir();opam.write_bytes(b'fixed opam')
        proof=self.runner.root/'proof.vo';proof.write_bytes(b'accepted proof object')
        self.runner.lock['opam_binary_sha256']=seq.digest(opam)
        seq.write_json(self.runner.root/'toolchain-identity.json',dict(packages=self.runner.lock['installed_packages'],installed_files={'proof.vo':seq.digest(proof)}))
        self.runner.verify_runtime()
        proof.write_bytes(b'changed proof object')
        with self.assertRaisesRegex(ValueError,'toolchain changed'):self.runner.verify_runtime()
    def test_named_package_recipe_cannot_silently_override_lock(self):
        source=self.base/'dep-src';source.mkdir();(source/'coq-fake.opam').write_text('unexpected recipe')
        archive=self.base/'dep.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:tar.add(source,arcname='dep')
        expected='expected recipe'
        self.runner.lock['dependency_pins']={'coq-fake':dict(url='unused',archive_sha256=seq.digest(archive),metadata=expected,metadata_sha256=hashlib.sha256(expected.encode()).hexdigest(),version='dev')}
        def fake_run(label,cmd):
            if label.startswith('download-'):shutil.copyfile(archive,cmd[5])
        with patch.object(self.runner,'run',side_effect=fake_run),self.assertRaisesRegex(ValueError,'Named dependency recipe mismatch'):self.runner.dependencies()

if __name__=='__main__':unittest.main()
