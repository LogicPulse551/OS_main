#!/usr/bin/env python3
"""Read-only, closed-profile SEQ RR candidate front end and premise intake.

This is NOT a C-to-SEQ translator or an optimization authorization service.
Only compiler-derived observations are established here. Linux proof obligations
remain open until a checked semantic connection is implemented.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
PROFILE = REPO / 'configs/optimization/seq-rr-lookup.contract.json'


class Rejected(ValueError):
    def __init__(self, code, detail):
        self.code, self.detail = code, detail
        super().__init__(code + ': ' + detail)


def digest(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read(path):
    return json.loads(pathlib.Path(path).read_text(encoding='utf-8'))


def write(path, value):
    with pathlib.Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


def snapshot_contract(out):
    """Retain exact input bytes, including failed and superseded contracts."""
    folder=out/'contract-inputs';folder.mkdir()
    paths=[PROFILE,REPO/'configs/optimization/seq.lock.json',REPO/'configs/maccconc.lock.json',pathlib.Path(__file__)]
    identities={}
    for path in paths:
        destination=folder/path.name
        with destination.open('xb') as stream:
            stream.write(path.read_bytes())
        identities[path.name]=digest(destination)
    return identities


def require(condition, code, detail):
    if not condition:
        raise Rejected(code, detail)


def safe_relative(value):
    require(isinstance(value, str), 'INVALID_PATH', 'expected relative path')
    path = pathlib.PurePosixPath(value)
    require(value and not path.is_absolute() and '..' not in path.parts and '\\' not in value
            and ':' not in value, 'INVALID_PATH', value)
    return path


def normalized_args(args, source, build, clang):
    replacements = [(str(clang), '<CLANG>'), (str(source), '<SOURCE>'), (str(build), '<BUILD>')]
    for old, new in sorted(replacements, key=lambda p: len(p[0]), reverse=True):
        args = [arg.replace(old, new) for arg in args]
    return args


def compiler_args(command_file, source, build, clang, expected):
    lines = [line for line in command_file.read_text().splitlines() if line.startswith('savedcmd_')]
    require(len(lines) == 1 and ' := ' in lines[0], 'COMMAND_FORMAT', str(command_file))
    args = shlex.split(lines[0].split(' := ', 1)[1])
    # Only an exactly registered compiler command is permitted. Never execute
    # a shell command from .cmd, including chained objtool or shell expansions.
    require(normalized_args(args, source, build, clang) == expected, 'COMMAND_DRIFT', str(command_file))
    require(args[0] == str(clang) and '-O2' in args and '-c' in args,
            'COMMAND_DRIFT', 'requires pinned normal O2 compilation')
    require(not any(a.startswith('-fsanitize') for a in args), 'DETECTION_BUILD', 'not a normal build')
    output, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg == '-o':
            index += 2
            continue
        if arg != '-c' and not arg.startswith('-Wp,-MMD,'):
            output.append(arg)
        index += 1
    return output


def json_stream(text):
    decoder, offset, values = json.JSONDecoder(), 0, []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        values.append(value)
    return values


def function_definition(text, name):
    definitions = [node for node in json_stream(text) if node.get('kind') == 'FunctionDecl'
                   and node.get('name') == name
                   and any(child.get('kind') == 'CompoundStmt' for child in node.get('inner', []))]
    require(len(definitions) == 1, 'FUNCTION_SHAPE', 'expected one definition of ' + name)
    return definitions[0]


def semantic_shape(node):
    """Deterministic parser fingerprint, not a semantic equivalence proof."""
    keys = ['kind', 'name', 'opcode', 'castKind', 'value', 'isArrow', 'valueCategory']
    value = {key: node[key] for key in keys if key in node}
    if 'type' in node:
        value['type'] = {k: v for k, v in node['type'].items() if k in ['qualType','desugaredQualType']}
    if 'referencedDecl' in node:
        value['referencedDecl'] = semantic_shape(node['referencedDecl'])
    if 'inner' in node:
        value['inner'] = [semantic_shape(child) for child in node['inner']]
    return value


def walk(node):
    yield node
    for child in node.get('inner', []):
        yield from walk(child)


def observations(node):
    members, calls, unsupported = [], [], []
    for item in walk(node):
        kind = item.get('kind', '')
        if kind == 'MemberExpr':
            members.append(dict(name=item['name'],type=item.get('type'),range=item.get('range')))
        if kind == 'CallExpr':
            refs = [n.get('referencedDecl', {}) for n in walk(item['inner'][0])
                    if n.get('kind') == 'DeclRefExpr']
            calls.append([dict(kind=r.get('kind'), name=r.get('name')) for r in refs])
        if kind in ['GCCAsmStmt', 'MSAsmStmt', 'AtomicExpr'] or 'volatile' in item.get('type', {}).get('qualType', ''):
            unsupported.append(kind)
    require(not unsupported, 'MARKED_OR_ASM_ACCESS', ','.join(unsupported))
    return dict(function=node['name'],function_type=node.get('type'),members=members,calls=calls,
                pointer_difference_observed=any(n.get('kind')=='BinaryOperator' and n.get('opcode')=='-'
                    and any('*' in c.get('type',{}).get('qualType','') for c in n.get('inner',[])) for n in walk(node)),
                interpretation='compiler syntax observations only, not an interference/effect/lifetime proof')


def assess_claims(path, subject, obligations):
    if path is None:
        return []
    data = read(path)
    require(isinstance(data, dict) and set(data) == {'schema_version','backend','subject_sha256','claims'},
            'CLAIM_SCHEMA', 'expected version/backend/subject/claims only')
    require(data['schema_version'] == 1 and data['backend'] == 'SEQ', 'BACKEND_MISMATCH', 'SEQ only')
    require(data['subject_sha256'] == subject, 'STALE_PREMISE', 'analysis subject changed')
    require(isinstance(data['claims'], list), 'CLAIM_SCHEMA', 'claims must be a list')
    result, seen = [], set()
    allowed = {'premise_id','kind','evidence_path','evidence_sha256','statement'}
    for claim in data['claims']:
        require(isinstance(claim,dict) and set(claim)==allowed, 'CLAIM_SCHEMA', 'unknown or missing claim field')
        pid = claim['premise_id']
        require(pid in obligations and pid not in seen, 'CLAIM_SCHEMA', 'unknown or duplicate premise')
        seen.add(pid)
        rel = safe_relative(claim['evidence_path']);evidence=(path.parent/rel).resolve()
        require(evidence.is_relative_to(path.parent.resolve()), 'INVALID_PATH', 'evidence escaped bundle')
        require(evidence.is_file() and digest(evidence)==claim['evidence_sha256'], 'EVIDENCE_DRIFT', str(rel))
        reasons = {'manual_assumption':'ASSUMPTION_NOT_PROOF', 'bounded_test':'TEST_NOT_PROOF',
                   'source_review':'REVIEW_NOT_PROOF', 'coq_artifact':'CERTIFICATE_VERIFIER_NOT_IMPLEMENTED'}
        require(claim['kind'] in reasons, 'CLAIM_KIND', 'unsupported evidence kind')
        result.append(dict(**claim,accepted_as_attachment=True,discharges_premise=False,reason=reasons[claim['kind']]))
    return result


class Recorder:
    def __init__(self, root):
        self.root = root
        (root/'commands').mkdir()
        self.count = 0

    def run(self, label, command, cwd):
        self.count += 1
        folder = self.root/'commands'/('%02d-'%self.count+label);folder.mkdir()
        record = dict(command=list(map(str,command)),cwd=str(cwd),started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        write(folder/'invocation.json',record)
        (folder/'frontend.py').write_bytes(pathlib.Path(__file__).read_bytes())
        try:
            with (folder/'stdout.log').open('wb') as out, (folder/'stderr.log').open('wb') as err:
                process = subprocess.run(command,cwd=cwd,stdout=out,stderr=err,timeout=120)
            record['exit_code'] = process.returncode
        except BaseException as error:
            record.update(exit_code=None,error=repr(error))
            raise
        finally:
            record['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            write(folder/'result.json',record)
        require(process.returncode == 0, 'COMPILER_FAILED', label)
        return folder/'stdout.log'


def inspect(source, build, clang, out, claims=None):
    source,build = source.resolve(),build.resolve()
    # Keep the registered driver spelling (clang may be a clang-23 symlink).
    # File hashing still follows the link and verifies the actual binary.
    clang = clang.absolute()
    profile = read(PROFILE)
    require(digest(REPO/'configs/optimization/seq.lock.json')==profile['seq_lock_sha256'] and
            digest(REPO/'configs/maccconc.lock.json')==profile['kernel_lock_sha256'],
            'DEPENDENCY_LOCK_DRIFT','registered backend/kernel lock changed')
    require(read(REPO/'configs/optimization/seq.lock.json')['commit']==profile['backend_commit'],
            'BACKEND_DRIFT','SEQ lock changed')
    require(digest(clang)==profile['clang_sha256'], 'COMPILER_DRIFT', str(clang))
    require(digest(build/'.config')==profile['config_sha256'], 'CONFIG_DRIFT', str(build))
    for name,expected in profile['source_files'].items():
        require(digest(source/safe_relative(name))==expected, 'SOURCE_DRIFT', name)
    recorder=Recorder(out);functions={};inputs={}
    for unit in profile['units']:
        args=compiler_args(build/safe_relative(unit['cmd_file']),source,build,clang,unit['normalized_argv'])
        pp=recorder.run('preprocess-'+unit['name'],[*args,'-E','-P'],build)
        require(digest(pp)==unit['preprocessed_sha256'], 'PREPROCESS_DRIFT', unit['name'])
        inputs[unit['name']]=dict(preprocessed_sha256=digest(pp),command=unit['normalized_argv'])
        for name,expected in unit['function_shapes'].items():
            ast=recorder.run('ast-'+name,[*args,'-fsyntax-only','-Xclang','-ast-dump=json','-Xclang','-ast-dump-filter='+name],build)
            node=function_definition(ast.read_text(),name)
            require(json_digest(semantic_shape(node))==expected,'FUNCTION_SHAPE',name)
            functions[name]=observations(node)
    lookup=functions['regcache_lookup_reg']
    require(sum(m['name']=='reg_defaults' for m in lookup['members'])==2 and
            lookup['calls']==[[{'kind':'FunctionDecl','name':'bsearch'}]], 'CANDIDATE_SHAPE','lookup access/call changed')
    subject_data=dict(profile_sha256=digest(PROFILE),source_files=profile['source_files'],inputs=inputs,
                      backend_commit=profile['backend_commit'],config_sha256=digest(build/'.config'),clang_sha256=digest(clang))
    subject=json_digest(subject_data)
    attachments=assess_claims(claims,subject,{p['id'] for p in profile['premises']})
    return dict(schema_version=1,task='O05',backend='SEQ',profile=profile['id'],status='candidate_only',
                frontend_completed=True,subject_sha256=subject,subject=subject_data,source=str(source),build=str(build),
                facts=functions,attachments=attachments,open_premises=profile['premises'],
                model_lowering_ready=False,model_refinement_proved=False,kernel_transform_allowed=False,
                rejection_codes=[p['rejection_code'] for p in profile['premises']],
                kernel_output_generated=False,observations=profile['observations'],refinement=profile['refinement'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=pathlib.Path,required=True)
    parser.add_argument('--build',type=pathlib.Path,required=True)
    parser.add_argument('--clang',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    parser.add_argument('--premises',type=pathlib.Path)
    parser.add_argument('--require-transform',action='store_true',help='return 3 when transformation is blocked')
    args=parser.parse_args()
    out=args.out.resolve()
    # No analysis is allowed to write into the supplied source or build tree.
    require(not any(out.is_relative_to(p.resolve()) for p in [args.source,args.build,REPO]),
            'OUTPUT_LOCATION','evidence must be outside source, build and code repository')
    out.mkdir(parents=True,exist_ok=False)
    write(out/'request.json',dict(source=str(args.source),build=str(args.build),clang=str(args.clang),
                                 premises=str(args.premises) if args.premises else None,require_transform=args.require_transform))
    try:
        snapshot_contract(out)
        result=inspect(args.source,args.build,args.clang,out,args.premises)
        status=3 if args.require_transform else 0
    except (Rejected,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        result=dict(schema_version=1,task='O05',backend='SEQ',status='rejected',frontend_completed=False,
                    kernel_transform_allowed=False,kernel_output_generated=False,
                    rejection_codes=[getattr(error,'code','INPUT_OR_EXECUTION_ERROR')],detail=str(error))
        status=2
    write(out/'result.json',result)
    write(out/'artifact-manifest.json',{p.relative_to(out).as_posix():digest(p) for p in out.rglob('*') if p.is_file()})
    print(json.dumps(dict(status=result['status'],kernel_transform_allowed=False,output=str(out)),ensure_ascii=False))
    return status


if __name__=='__main__':
    sys.exit(main())
