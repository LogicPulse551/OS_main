"""Reproduction runner rejection, preservation and failure evidence tests."""
import hashlib, importlib.util, json, pathlib, sys, tempfile, unittest
from unittest.mock import patch
REPO=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('b02_runner',REPO/'scripts/optimization/b02.py')
b02=importlib.util.module_from_spec(spec);spec.loader.exec_module(b02)

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=pathlib.Path(self.temp.name);self.root=self.base/'env';self.logs=self.base/'records'
        self.runner=b02.Runner(self.root,self.logs)
        self.fake_repo=self.base/'repo';(self.fake_repo/'configs/optimization').mkdir(parents=True)
        self.source=self.base/'source';self.source.mkdir()
        (self.source/'a.v').write_text('Check nat.\n',encoding='utf-8')
        self.write_lock({'a.v':b02.digest(self.source/'a.v')})
    def write_lock(self,files):
        (self.fake_repo/'configs/optimization/b02.lock.json').write_text(json.dumps({'source_files':files}),encoding='utf-8')
    def test_changed_source_is_rejected_before_work_creation(self):
        (self.source/'a.v').write_text('Axiom bogus : False.',encoding='utf-8')
        with patch.object(b02,'REPO',self.fake_repo),self.assertRaisesRegex(ValueError,'identity mismatch'):
            self.runner.source(self.source)
        self.assertFalse((self.root/'source-01').exists())
    def test_compiled_upstream_artifact_is_not_copied(self):
        (self.source/'a.vo').write_bytes(b'old compiled proof')
        with patch.object(b02,'REPO',self.fake_repo):self.runner.source(self.source)
        self.assertEqual((self.root/'source-01/a.v').read_bytes(),(self.source/'a.v').read_bytes())
        self.assertFalse((self.root/'source-01/a.vo').exists())
    def test_existing_work_is_preserved(self):
        work=self.root/'source-01';work.mkdir();(work/'marker').write_text('baseline')
        with patch.object(b02,'REPO',self.fake_repo),self.assertRaises(FileExistsError):self.runner.source(self.source)
        self.assertEqual((work/'marker').read_text(),'baseline')
    def test_manifest_parent_traversal_rejected(self):
        self.write_lock({'../a.v':'0'*64})
        with patch.object(b02,'REPO',self.fake_repo),self.assertRaisesRegex(ValueError,'Unsafe source path'):self.runner.source(self.source)
    def test_failed_and_expected_rejection_commands_both_retained(self):
        with self.assertRaises(SystemExit):self.runner.run('trial',[sys.executable,'-c','raise SystemExit(3)'])
        self.runner.run('trial',[sys.executable,'-c','raise SystemExit(3)'],expected_exit=3)
        records=[json.loads(p.read_text()) for p in self.logs.glob('*/result.json')]
        self.assertEqual(len(records),2)
        self.assertEqual(sorted(r['expected_exit_matched'] for r in records),[False,True])
        self.assertTrue(all(r['exit_code']==3 for r in records))
    def test_launch_failure_is_recorded(self):
        with self.assertRaises(OSError):self.runner.run('missing',[str(self.base/'no-such-program')])
        p=next(self.logs.glob('*/result.json'));r=json.loads(p.read_text())
        self.assertIsNone(r['exit_code']);self.assertFalse(r['expected_exit_matched']);self.assertIn('error',r)
    def test_changed_toolchain_is_rejected_and_recorded(self):
        (self.fake_repo/'configs/optimization/b02.lock.json').write_text(json.dumps({'installed_packages':{'coq':'8.13.1'}}))
        attempt=self.base/'versions';attempt.mkdir();(attempt/'stdout.log').write_text('# Name Version\ncoq 8.14.0\n')
        with patch.object(b02,'REPO',self.fake_repo),patch.object(self.runner,'run',return_value=attempt),self.assertRaisesRegex(SystemExit,'versions do not match'):
            self.runner.verify_versions()
        self.assertFalse(json.loads((attempt/'version-check.json').read_text())['passed'])
    def test_matching_toolchain_is_accepted(self):
        (self.fake_repo/'configs/optimization/b02.lock.json').write_text(json.dumps({'installed_packages':{'coq':'8.13.1'}}))
        attempt=self.base/'versions';attempt.mkdir();(attempt/'stdout.log').write_text('# Name Version\ncoq 8.13.1\n')
        with patch.object(b02,'REPO',self.fake_repo),patch.object(self.runner,'run',return_value=attempt):self.runner.verify_versions()
        self.assertTrue(json.loads((attempt/'version-check.json').read_text())['passed'])

if __name__=='__main__':unittest.main()
