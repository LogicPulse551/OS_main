import copy
import json
from pathlib import Path
import struct
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from kconc import artifacts as a
from kconc.manifest import normalize_manifest, ManifestError


def note(value=b'01234567890123456789'):
    return struct.pack('<III',4,len(value),3)+b'GNU\0'+value


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.build=self.root/'build';self.build.mkdir()
        self.driver=self.root/'clang';self.driver.write_bytes(b'test compiler')
        self.compiler=patch.object(a,'CLANG_SHA',a.sha(self.driver));self.compiler.start()
        self.addCleanup(self.compiler.stop);self.addCleanup(self.tmp.cleanup)
        config='\n'.join(k+'='+v for k,v in a.read(a.POLICY)['detection']['required'].items())+'\n'
        (self.build/'.config').write_text(config)
        n=note();h=bytearray(64);h[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',h,18,62)
        struct.pack_into('<Q',h,40,64);struct.pack_into('<HH',h,58,64,1)
        s=bytearray(64);struct.pack_into('<I',s,4,7);struct.pack_into('<QQ',s,24,128,len(n))
        (self.build/'vmlinux').write_bytes(h+s+n)
        for name in ['arch/x86/boot/bzImage','System.map','include/config/kernel.release','drivers/base/regmap/.regcache.o.cmd']:
            p=self.build/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
        (self.build/'drivers/base/regmap/.regcache.o.cmd').write_text('savedcmd := '+str(self.driver)+' -O2 -fsanitize=kernel-address -fsanitize-coverage=trace-pc\n')
        self.steps=self.root/'steps.json';self.steps.write_text('[{"exit_code":0}]')
        self.llvm=self.root/'llvm.json';self.llvm.write_text('{}')
        self.receipt=self.root/'receipt.json'
        self.data=dict(stage='kernel',source_commit=a.PIN,steps=str(self.steps),llvm_identity=a.ref(self.llvm),artifacts=[a.ref(self.build/n) for n in ['arch/x86/boot/bzImage','vmlinux','.config','System.map']])
        self.save(self.receipt,self.data)
        self.manifest=self.root/'identity.json';self.save(self.manifest,a.from_receipt(self.receipt))

    def save(self,path,value):path.write_text(json.dumps(value))
    def reject_change(self,key,value):
        m=a.read(self.manifest);m[key]=value;self.save(self.manifest,a.seal(m))
        with self.assertRaises(ValueError):a.check_identity(self.manifest)

    def test_valid_receipt_bound_original(self):
        m=a.check_identity(self.manifest)
        self.assertEqual(m['variant'],'original');self.assertFalse(m['performance_config_eligible'])
    def test_hash_tamper(self):
        (self.build/'arch/x86/boot/bzImage').write_text('changed')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):a.check_identity(self.manifest)
    def test_config_tamper(self):
        (self.build/'.config').write_text('CONFIG_KCOV=n')
        with self.assertRaises(ValueError):a.check_identity(self.manifest)
    def test_relabel_repaired(self):self.reject_change('variant','repaired')
    def test_relabel_optimized(self):self.reject_change('variant','optimized')
    def test_relabel_performance(self):self.reject_change('purpose','performance')
    def test_relabel_family(self):self.reject_change('family','different-family')
    def test_missing_rejected(self):
        m=a.missing('optimized','detection','linux-original','O06 not executed',self.manifest)
        self.assertIsNone(m['artifacts']);self.save(self.root/'absent.json',m)
        with self.assertRaisesRegex(ValueError,'variant_not_generated'):a.check_identity(self.root/'absent.json')
    def test_missing_wrong_parent(self):
        with self.assertRaisesRegex(ValueError,'parent mismatch'):a.missing('repaired','performance','linux-original','absent',self.manifest)
    def test_wrong_expected_purpose(self):
        with self.assertRaisesRegex(ValueError,'purpose mismatch'):a.check_identity(self.manifest,'performance')
    def test_failed_build(self):
        self.steps.write_text('[{"exit_code":2}]')
        with self.assertRaisesRegex(ValueError,'commands failed'):a.from_receipt(self.receipt)
    def test_unknown_builder(self):
        self.data['task']='O06';self.save(self.receipt,self.data)
        with self.assertRaisesRegex(ValueError,'unregistered builder'):a.from_receipt(self.receipt)
    def test_unknown_kind_cannot_impersonate_k02(self):
        self.data['kind']='future.optimized-builder';self.save(self.receipt,self.data)
        with self.assertRaisesRegex(ValueError,'unregistered builder'):a.from_receipt(self.receipt)
    def test_wrong_pin(self):
        self.data['source_commit']='0'*40;self.save(self.receipt,self.data)
        with self.assertRaisesRegex(ValueError,'unregistered source'):a.from_receipt(self.receipt)
    def test_bad_compiler(self):
        self.driver.write_text('different compiler')
        with self.assertRaisesRegex(ValueError,'compiler'):a.from_receipt(self.receipt)
    def test_elf_id(self):self.assertEqual(a.elf_id(self.build/'vmlinux'),b'01234567890123456789'.hex())
    def test_wrong_arch(self):
        p=self.build/'vmlinux';d=bytearray(p.read_bytes());struct.pack_into('<H',d,18,243);p.write_bytes(d)
        with self.assertRaisesRegex(ValueError,'x86_64'):a.elf_id(p)
    def test_truncated_note(self):
        with self.assertRaises(ValueError):a.notes_id(note()[:-2])
    def test_duplicate_build_id(self):
        with self.assertRaises(ValueError):a.notes_id(note()+note())
    def test_normal_o2_profile(self):
        text='\n'.join(k+'='+v for k,v in a.read(a.POLICY)['performance']['required'].items())
        self.assertTrue(a.check_profile('performance',text,'clang -O2 -c regcache.c'))
        with self.assertRaises(ValueError):a.check_profile('performance',text+'\nCONFIG_KCOV=y','clang -O2')
        with self.assertRaises(ValueError):a.check_profile('performance',text,'clang -O2 -fsanitize-coverage=trace-pc')
        with self.assertRaises(ValueError):a.check_profile('performance',text,'clang -O0')
    def test_load_requires_runtime(self):
        with self.assertRaises(ManifestError):normalize_manifest(dict(schema_version=1,operation='artifact.loaded',inputs=dict(identity='identity.json')),self.root)
    def test_check_is_offline_without_runtime(self):
        m=normalize_manifest(dict(schema_version=1,operation='artifact.check',inputs=dict(identity='identity.json')),self.root)
        self.assertEqual(m['runtime'],{})
    def guest_fixture(self):
        m=a.read(self.manifest)
        return m, dict(release=m['release'],cmdline='root=/dev/vda2 kconc.identity='+m['identity_id'],modules=''), (self.build/'.config').read_bytes(), note()
    def test_guest_matches(self):
        m,g,c,n=self.guest_fixture();self.assertEqual(a.check_guest(m,g,c,n)['gnu_build_id'],m['gnu_build_id'])
    def test_wrong_loaded_build_id(self):
        m,g,c,n=self.guest_fixture()
        with self.assertRaisesRegex(ValueError,'build ID'):a.check_guest(m,g,c,note(b'wrong build ID......'))
    def test_wrong_loaded_config(self):
        m,g,c,n=self.guest_fixture()
        with self.assertRaisesRegex(ValueError,'config mismatch'):a.check_guest(m,g,c+b'\n',n)
    def test_wrong_loaded_release(self):
        m,g,c,n=self.guest_fixture();g['release']='different'
        with self.assertRaisesRegex(ValueError,'release mismatch'):a.check_guest(m,g,c,n)
    def test_wrong_loaded_token(self):
        m,g,c,n=self.guest_fixture();g['cmdline']='root=/dev/vda2'
        with self.assertRaisesRegex(ValueError,'token mismatch'):a.check_guest(m,g,c,n)
    def test_loaded_extra_module(self):
        m,g,c,n=self.guest_fixture();g['modules']='external_module 500 0 - Live 0x123'
        with self.assertRaisesRegex(ValueError,'unregistered loaded modules'):a.check_guest(m,g,c,n)
    def repair_fixture(self):
        parent_data={**self.data,'task':'K10','kind':'kconc.control-kernel.build','family':'rmw','passed':True,'checks':{'build':True}}
        self.save(self.receipt,parent_data);self.save(self.manifest,a.from_receipt(self.receipt))
        child=self.root/'repaired';shutil.copytree(self.build,child)
        (child/'arch/x86/boot/bzImage').write_bytes(b'new repaired image')
        patch_path=REPO/'patches/maccconc/0004-k11-rmw-repair.patch'
        r={**parent_data,'task':'K11','kind':'kconc.repaired-kernel.build',
           'accepted_parent_build_record':a.ref(self.receipt),
           'repair_patch':dict(path=patch_path.relative_to(REPO).as_posix(),sha256=a.sha(patch_path)),
           'artifacts':[a.ref(child/n) for n in ['arch/x86/boot/bzImage','vmlinux','.config','System.map']]}
        path=self.root/'repair-receipt.json';self.save(path,r)
        return path,r,child
    def test_repair_parent_bound(self):
        p,r,b=self.repair_fixture();m=a.from_receipt(p,self.manifest)
        self.assertEqual(m['relation']['parent_identity_id'],a.read(self.manifest)['identity_id'])
        self.assertEqual(m['variant'],'repaired')
    def test_repair_without_parent(self):
        p,r,b=self.repair_fixture()
        with self.assertRaisesRegex(ValueError,'requires its original'):a.from_receipt(p)
    def test_repair_wrong_family(self):
        p,r,b=self.repair_fixture();r['family']='mutex';self.save(p,r)
        with self.assertRaisesRegex(ValueError,'parent family'):a.from_receipt(p,self.manifest)
    def test_repair_wrong_parent_receipt(self):
        p,r,b=self.repair_fixture();r['accepted_parent_build_record']=a.ref(self.steps);self.save(p,r)
        with self.assertRaisesRegex(ValueError,'parent receipt mismatch'):a.from_receipt(p,self.manifest)
    def test_repair_alias_rejected(self):
        p,r,b=self.repair_fixture();r['artifacts']=self.data['artifacts'];self.save(p,r)
        with self.assertRaisesRegex(ValueError,'cannot alias'):a.from_receipt(p,self.manifest)


if __name__=='__main__':unittest.main()
