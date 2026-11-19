#!/usr/bin/env python3
"""Read-only first-install/rollback guard: pinned Ed25519 signature AND approval."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import tempfile

ROOT = Path("/opt/gamesense-radar")
SHA = re.compile(r"[a-f0-9]{64}")
CORE_FILES = {"radarserver", "server/LicenseAuthority.php", "server/license-authority-cli.php"}
MAP_FILES = {'maps/de_anubis/LICENSE', 'maps/de_ancient/overview.png', 'maps/de_thera/meta.json5', 'maps/cs_office/meta.json5', 'maps/de_dust2/overview.png', 'maps/de_mirage/overview.png', 'maps/de_train/meta.json5', 'maps/de_golden/meta.json5', 'maps/de_inferno/meta.json5', 'maps/cs_agency/meta.json5', 'maps/de_cache/meta.json5', 'maps/de_grail/meta.json5', 'maps/de_palacio/meta.json5', 'maps/de_overpass/overview.png', 'maps/de_anubis/overview.png', 'maps/de_palacio/overview.png', 'maps/cs_office/overview.png', 'maps/de_golden/overview.png', 'maps/de_anubis/meta.json5', 'maps/cs_agency/overview.png', 'maps/de_ancient/LICENSE', 'maps/de_vertigo/overview.png', 'maps/de_vertigo/meta.json5', 'maps/底图来源与许可.md', 'maps/de_mirage/meta.json5', 'maps/de_inferno/overview.png', 'maps/de_train/overview.png', 'maps/cs_italy/meta.json5', 'maps/de_grail/overview.png', 'maps/de_dust2/meta.json5', 'maps/de_nuke/meta.json5', 'maps/de_cache/overview.png', 'maps/de_ancient/meta.json5', 'maps/cs_italy/overview.png', 'maps/de_overpass/meta.json5', 'maps/de_nuke/overview.png', 'maps/de_thera/overview.png'}
FILES = CORE_FILES | MAP_FILES

OPENSSL = Path('/usr/bin/openssl')
SIGNING_CONTEXT = b'gamesense-release-manifest-v1\n'
ED25519_SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')

def regular(p, owner, limit=None):
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode) or owner and (s.st_uid != 0 or s.st_mode & 0o022) or limit is not None and s.st_size > limit:
        raise ValueError("untrusted release file")
    return p.read_bytes()

def directory(p, owner):
    s = p.lstat()
    if not stat.S_ISDIR(s.st_mode) or owner and (s.st_uid != 0 or s.st_mode & 0o022):
        raise ValueError("untrusted release directory")

def document(raw):
    if len(raw) > 16384: raise ValueError("oversized metadata")
    def pairs(items):
        d={}
        for k,v in items:
            if k in d: raise ValueError("duplicate metadata field")
            d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs)

def configuration(root, owner):
    for d in (root,root/"admin",root/"releases"):
        directory(d,owner)
    if owner:
        for p in root.parents:
            directory(p,True)
    policy=document(regular(root/"admin/policy.json",owner,16384))
    approved=document(regular(root/"admin/approved-releases.json",owner,16384))
    if not isinstance(policy,dict) or set(policy)!={"schema","security_epoch","public_origin","app_id"} or type(policy["schema"]) is not int or type(policy["security_epoch"]) is not int or policy["schema"]!=1 or policy["security_epoch"]!=1 or type(policy["app_id"]) is not int or policy["app_id"]<1:
        raise ValueError("deployment policy invalid")
    if not isinstance(policy["public_origin"],str) or not re.fullmatch(r"https://[0-9.]+",policy["public_origin"]):
        raise ValueError("IP HTTPS policy required")
    ip=ipaddress.ip_address(policy["public_origin"][8:])
    if ip.version!=4 or not ip.is_global or policy["public_origin"]!="https://"+str(ip):
        raise ValueError("canonical public IPv4 policy required")
    if not isinstance(approved,dict) or set(approved)!={"schema","manifest_sha256"} or type(approved["schema"]) is not int or approved["schema"]!=1 or not isinstance(approved["manifest_sha256"],list) or len(approved["manifest_sha256"])>64 or any(not isinstance(x,str) or not SHA.fullmatch(x) for x in approved["manifest_sha256"]):
        raise ValueError("approval registry invalid")
    trust=document(regular(root/'admin/release-trust.json',owner,4096))
    if not isinstance(trust,dict) or set(trust)!={'schema','algorithm','public_key_sha256'} or type(trust['schema']) is not int or trust['schema']!=1 or trust['algorithm']!='Ed25519' or not isinstance(trust['public_key_sha256'],str) or not SHA.fullmatch(trust['public_key_sha256']):
        raise ValueError('release signing trust not configured')
    key=regular(root/'admin/release-signing-public.der',owner,44)
    if len(key)!=44 or not key.startswith(ED25519_SPKI_PREFIX) or hashlib.sha256(key).hexdigest()!=trust['public_key_sha256']:
        raise ValueError('release signing key mismatch')
    return policy,approved,key

def signature(raw, key, sig):
    # Do not implement crypto, accept a key supplied in the manifest, consult PATH,
    # load caller OpenSSL providers/config, or fall back when crypto is unavailable.
    if len(sig)!=64: raise ValueError('invalid Ed25519 signature length')
    s=OPENSSL.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:
        raise ValueError('untrusted cryptographic runtime')
    with tempfile.TemporaryDirectory(prefix='gamesense-release-proof-') as d:
        p=Path(d)
        for n,data in [('public.der',key),('signature.bin',sig),('message.bin',SIGNING_CONTEXT+raw)]:
            with (p/n).open('xb') as f:f.write(data)
            (p/n).chmod(0o600)
        try:
            r=subprocess.run([str(OPENSSL),'pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(p/'public.der'),'-sigfile',str(p/'signature.bin'),'-rawin','-in',str(p/'message.bin')],stdin=subprocess.DEVNULL,capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin','OPENSSL_CONF':'/dev/null','LC_ALL':'C'})
        except subprocess.TimeoutExpired as e:
            raise ValueError('release signature runtime unavailable') from e
    if r.returncode!=0: raise ValueError('release signature invalid')

def release(root, digest, owner, policy, approved, key):
    if not isinstance(digest,str) or not SHA.fullmatch(digest):raise ValueError('manifest hash required')
    if digest not in approved['manifest_sha256']:raise ValueError('release not approved')
    p=root/'releases'/digest
    directory(p,owner);directory(p/'server',owner)
    raw=regular(p/'manifest.json',owner,16384)
    if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('manifest integrity mismatch')
    signature(raw,key,regular(p/'manifest.ed25519.sig',owner,64))
    m=document(raw)
    if not isinstance(m,dict) or set(m)!={'schema','security_epoch','public_origin','app_id','entrypoint','files'} or any(type(m.get(k)) is not type(v) or m.get(k)!=v for k,v in policy.items()) or m['entrypoint']!='remote-device-proof-v1' or not isinstance(m['files'],dict) or set(m['files'])!=FILES:
        raise ValueError('release policy/entrypoint mismatch')
    # Every signed asset is immutable and every leaf/parent is checked, including
    # metadata/license files. No unsigned extras, symlinks or traversed parents.
    actual = set()
    for q in p.rglob('*'):
        st = q.lstat()
        if stat.S_ISDIR(st.st_mode):
            directory(q,owner)
        else:
            regular(q,owner)
            actual.add(q.relative_to(p).as_posix())
    if actual != FILES | {'manifest.json','manifest.ed25519.sig'}:
        raise ValueError('unexpected or missing release files')
    for name in FILES:
        for parent in (p/name).parents:
            if parent == p: break
            directory(parent,owner)
    for name,d in m['files'].items():
        if not isinstance(d,str) or not SHA.fullmatch(d) or hashlib.sha256(regular(p/name,owner)).hexdigest()!=d:
            raise ValueError('release artifact integrity mismatch')
    if owner and not (p/'radarserver').stat().st_mode & stat.S_IXUSR:raise ValueError('service binary not executable')

def verify_first(root, target, owner=True):
    # Read-only FIRST-install acceptance, not an installer or implicit approval.
    # lexists also refuses dangling symlinks and non-symlink current objects.
    if os.path.lexists(root/'current'):raise ValueError('first install requires absent current')
    policy,approved,key=configuration(root,owner)
    release(root,target,owner,policy,approved,key)
    return {'first_install_allowed':True,'target':target,'signature_verified':True,'approved':True,'activated':False,'requires_reauthentication':True}

def verify(root, expected, target, owner=True):
    # Production CLI never exposes root/owner overrides; library arguments allow
    # isolated tests only, never a configurable public deployment destination.
    if not isinstance(expected,str) or not isinstance(target,str) or not SHA.fullmatch(expected) or not SHA.fullmatch(target) or expected==target:
        raise ValueError('two different manifest hashes required')
    policy,approved,key=configuration(root,owner)
    if not (root/'current').is_symlink() or os.readlink(root/'current')!='releases/'+expected:
        raise ValueError('current release changed or untrusted pointer')
    for digest in (expected,target):release(root,digest,owner,policy,approved,key)
    return {"rollback_allowed":True,"expected_current":expected,"target":target,"security_epoch":1,"signature_verified":True,"approved":True,"database_rollback":False,"config_rollback":False,"requires_reauthentication":True}

def main():
    try:
        if len(sys.argv)!=3 or os.name!="posix" or os.geteuid()!=0:
            raise ValueError("Linux administrator required")
        answer=verify_first(ROOT,sys.argv[2]) if sys.argv[1]=='--first-install' else verify(ROOT,sys.argv[1],sys.argv[2])
        print(json.dumps(answer))
        return 0
    except (OSError,ValueError,TypeError,KeyError):
        print("RELEASE_DENIED: unsigned, untrusted, unapproved, incompatible or modified release/current state",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
