"""Evidence cannot authorize a transform; stale/changed inputs are rejected."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

REPO=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('contract',REPO/'scripts/optimization/seq_rr_contract.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.evidence=self.root/'evidence.txt'
        self.evidence.write_text('user attachment: no independent proof')
        self.claims=self.root/'claims.json'
        self.data=dict(schema_version=1,backend='SEQ',subject_sha256='a'*64,claims=[dict(
            premise_id='P01',kind='manual_assumption',evidence_path='evidence.txt',
            evidence_sha256=c.digest(self.evidence),statement='assume live and non-overlapping')])

    def assess(self):
        self.claims.write_text(json.dumps(self.data))
        return c.assess_claims(self.claims,'a'*64,{'P01'})

    def rejects(self,code):
        with self.assertRaises(c.Rejected) as ctx:self.assess()
        self.assertEqual(ctx.exception.code,code)

    def test_valid_review_attachment_is_not_a_proof(self):
        for kind in ['manual_assumption','source_review','coq_artifact','bounded_test']:
            with self.subTest(kind=kind):
                self.data['claims'][0]['kind']=kind
                result=self.assess()[0]
                self.assertTrue(result['accepted_as_attachment'])
                self.assertFalse(result['discharges_premise'])

    def test_search_success_cannot_satisfy_a_premise(self):
        self.data['claims'][0].update(kind='bounded_test',statement='100000 schedules; no errors')
        self.assertEqual(self.assess()[0]['reason'],'TEST_NOT_PROOF')

    def test_stale_subject_rejected(self):
        self.data['subject_sha256']='b'*64;self.rejects('STALE_PREMISE')

    def test_other_backend_rejected(self):
        self.data['backend']='B02';self.rejects('BACKEND_MISMATCH')

    def test_changed_attachment_rejected(self):
        self.evidence.write_text('changed');self.rejects('EVIDENCE_DRIFT')

    def test_missing_attachment_rejected(self):
        self.data['claims'][0]['evidence_path']='missing.txt';self.rejects('EVIDENCE_DRIFT')

    def test_self_declared_verified_rejected(self):
        self.data['claims'][0]['verified']=True;self.rejects('CLAIM_SCHEMA')

    def test_injected_global_authorization_rejected(self):
        self.data['kernel_transform_allowed']=True;self.rejects('CLAIM_SCHEMA')

    def test_duplicate_claim_rejected(self):
        self.data['claims'].append(copy.deepcopy(self.data['claims'][0]));self.rejects('CLAIM_SCHEMA')

    def test_unknown_premise_rejected(self):
        self.data['claims'][0]['premise_id']='ww_rf';self.rejects('CLAIM_SCHEMA')

    def test_unknown_verifier_rejected(self):
        self.data['claims'][0]['kind']='trusted';self.rejects('CLAIM_KIND')

    def test_paths_cannot_escape_evidence_bundle(self):
        for name in ['../evidence.txt','/etc/passwd','C:/file','a\\b']:
            with self.subTest(name=name):
                self.data['claims'][0]['evidence_path']=name;self.rejects('INVALID_PATH')

    def test_symlink_cannot_escape_bundle(self):
        outside=self.root.parent/(self.root.name+'-outside');outside.write_text('outside')
        self.addCleanup(outside.unlink)
        link=self.root/'link'
        try:link.symlink_to(outside)
        except OSError:self.skipTest('symlink unavailable')
        self.data['claims'][0].update(evidence_path='link',evidence_sha256=c.digest(outside))
        self.rejects('INVALID_PATH')

    def test_missing_claims_leave_obligations_open(self):
        self.assertEqual(c.assess_claims(None,'a'*64,{'P01'}),[])

    def test_clang_declaration_stream_selects_definition(self):
        declaration=dict(kind='FunctionDecl',name='f',inner=[])
        definition=dict(kind='FunctionDecl',name='f',inner=[{'kind':'CompoundStmt'}])
        self.assertEqual(c.function_definition(json.dumps(declaration)+'\n'+json.dumps(definition),'f'),definition)
        with self.assertRaises(c.Rejected):c.function_definition(json.dumps(declaration),'f')
        with self.assertRaises(c.Rejected):c.function_definition(json.dumps(definition)*2,'f')

    def test_parser_ids_do_not_change_shape_but_type_and_operator_do(self):
        left=dict(kind='BinaryOperator',id='0x1',opcode='+',type={'qualType':'size_t','typeAliasDeclId':'0xa'})
        right=copy.deepcopy(left);right['id']='0x2';right['type']['typeAliasDeclId']='0xb'
        self.assertEqual(c.semantic_shape(left),c.semantic_shape(right))
        right['opcode']='-';self.assertNotEqual(c.semantic_shape(left),c.semantic_shape(right))
        right=copy.deepcopy(left);right['type']['qualType']='unsigned int'
        self.assertNotEqual(c.semantic_shape(left),c.semantic_shape(right))

    def test_marked_accesses_are_not_plain_memory(self):
        for item in [{'kind':'GCCAsmStmt'},{'kind':'AtomicExpr'},{'kind':'MemberExpr','type':{'qualType':'volatile int'},'name':'f'}]:
            with self.subTest(item=item),self.assertRaises(c.Rejected):
                c.observations(dict(kind='FunctionDecl',name='f',inner=[item]))

    def test_exact_commands_reject_o0_shell_and_instrumentation(self):
        path=self.root/'.x.cmd';source=self.root/'src';build=self.root/'build';clang=self.root/'clang'
        args=[str(clang),'-O2','-c','-o','x.o','x.c'];expected=c.normalized_args(args,source,build,clang)
        path.write_text('savedcmd_x := '+ ' '.join(args))
        self.assertEqual(c.compiler_args(path,source,build,clang,expected),[str(clang),'-O2','x.c'])
        for altered in [args[:1]+['-O0']+args[2:],args+[';','echo','injected'],args+['-fsanitize=kernel-address']]:
            path.write_text('savedcmd_x := '+' '.join(altered))
            with self.assertRaises(c.Rejected):c.compiler_args(path,source,build,clang,expected)

    def test_contract_does_not_claim_lowering_or_other_backend(self):
        profile=c.read(c.PROFILE)
        self.assertEqual(profile['backend'],'SEQ')
        self.assertFalse(profile['source_recognition']['automatic_c_lowering'])
        self.assertFalse(profile['proof_boundary']['kernel_transform_supported'])
        self.assertEqual(len(profile['premises']),8)

    def test_exact_contract_and_locks_retained_without_overwrite(self):
        hashes=c.snapshot_contract(self.root)
        self.assertEqual(hashes[c.PROFILE.name],c.digest(c.PROFILE))
        self.assertEqual(hashes['seq.lock.json'],c.digest(REPO/'configs/optimization/seq.lock.json'))
        with self.assertRaises(FileExistsError):c.snapshot_contract(self.root)


if __name__=='__main__':unittest.main()
