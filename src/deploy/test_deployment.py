"""Isolated deployment-policy tests: never invokes services, sockets or game code."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import shutil
import unittest
import uuid
import subprocess
from unittest.mock import patch

import render
import release_check as guard

class DeploymentTests(unittest.TestCase):
    def setUp(self):
        base=Path(os.environ.get('GS_DEPLOY_TEST_DIR',tempfile.gettempdir())).resolve()
        base.mkdir(parents=True,exist_ok=True)
        self.root=base/('gs-deploy-test-'+uuid.uuid4().hex)
        # Python 3.13's special Windows 0700 DACL is incompatible with this
        # restricted executor. Synthetic-only tests inherit the workspace ACL.
        self.root.mkdir(mode=0o700 if os.name=='posix' else 0o755)
        def cleanup():
            assert self.root.resolve().parent==base and self.root.name.startswith('gs-deploy-test-')
            shutil.rmtree(self.root)
        self.addCleanup(cleanup)
        self.config={"schema":1,"public_origin":"https://118.25.176.85","app_id":7,"guyi_project":"/opt/guyi-access/current","php_binary":"/usr/bin/php8.2","security_epoch":1}
    def write_config(self,c=None):
        p=self.root/'input.json';p.write_text(json.dumps(self.config if c is None else c),encoding='utf-8');return p
    def test_render_offline_and_empty_approvals(self):
        out=self.root/'rendered';files=render.render(self.write_config(),out)
        self.assertEqual(len(files),12)
        self.assertEqual(json.loads((out/'approved-rollouts.json').read_text())['plan_sha256'],[])
        self.assertEqual(json.loads((out/'approved-releases.json').read_text())['manifest_sha256'],[])
        self.assertIsNone(json.loads((out/'release-trust.json').read_text())['public_key_sha256'])
        self.assertFalse((out/'release-signing-public.der').exists())
        service=(out/'gamesense-radar.service').read_text()
        for item in ['User=gamesense-radar','-listen 127.0.0.1:18081','ProtectSystem=strict','CapabilityBoundingSet=','GUYI_CONFIG_FILE=/etc/gamesense-radar/license-db.php','IPAddressDeny=any']:
            self.assertIn(item,service)
        proxy=(out/'gamesense-radar-upstream.conf').read_text()
        for item in ['proxy_set_header Host "118.25.176.85"','X-GS-TLS "1"','X-GS-Client-IP $remote_addr','proxy_next_upstream off','proxy_request_buffering off','access_log off']:
            self.assertIn(item,proxy)
        self.assertNotIn('@@',''.join(p.read_text() for p in out.iterdir()))
    def test_invalid_config_does_not_write(self):
        bad=[('public_origin','http://118.25.176.85'),('public_origin','https://127.0.0.1'),('public_origin','https://118.25.176.85/path'),('public_origin','https://token@118.25.176.85'),('public_origin','https://118.25.176.85?token=x'),('public_origin','https://csleida.cc.cd'),('app_id',0),('app_id',True),('schema',True),('security_epoch',0),('guyi_project','/opt/../root'),('guyi_project','/opt/x\nExecStart=/bin/false'),('php_binary','/usr/bin/php;id'),('token','SYNTHETIC')]
        for k,v in bad:
            c=self.config.copy();c[k]=v;out=self.root/'not-created'
            with self.subTest(field=k,value=v),self.assertRaises((ValueError,TypeError)):
                render.render(self.write_config(c),out)
            self.assertFalse(out.exists())
    def test_runtime_mount_is_explicitly_readonly(self):
        out=self.root/'runtime-readonly';render.render(self.write_config(),out)
        properties=dict(line.split('=',1) for line in (out/'gamesense-radar.service').read_text().splitlines() if '=' in line)
        self.assertEqual(properties['ProtectSystem'],'strict')
        self.assertEqual(properties['ReadOnlyPaths'],'/run')
        self.assertEqual(properties['PrivateTmp'],'yes')
        self.assertNotIn('ReadWritePaths',properties)
    def test_duplicate_fields_reject(self):
        p=self.write_config();p.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):render.render(p,self.root/'no-output')
    def test_existing_output_unchanged(self):
        out=self.root/'existing';out.mkdir();f=out/'keep';f.write_bytes(b'pristine')
        with self.assertRaises(ValueError):render.render(self.write_config(),out)
        self.assertEqual(f.read_bytes(),b'pristine')
    def fixture(self):
        if os.name!='posix' or not guard.OPENSSL.is_file():
            self.skipTest('real OpenSSL Ed25519 fixture requires Linux; native server suite mandatory')
        r=self.root/'runtime';(r/'admin').mkdir(parents=True);(r/'releases').mkdir()
        policy={k:self.config[k] for k in ['schema','security_epoch','public_origin','app_id']}
        (r/'admin/policy.json').write_text(json.dumps(policy))
        key=self.root/'synthetic-signing.pem';self.crypto('genpkey','-algorithm','ED25519','-out',key)
        der=r/'admin/release-signing-public.der';self.crypto('pkey','-in',key,'-pubout','-outform','DER','-out',der)
        (r/'admin/release-trust.json').write_text(json.dumps({'schema':1,'algorithm':'Ed25519','public_key_sha256':hashlib.sha256(der.read_bytes()).hexdigest()}))
        hashes=[]
        for version in ['a','b']:
            data={n:((Path(__file__).resolve().parent.parent/'dist'/n).read_bytes() if n in guard.MAP_FILES else ('SYNTHETIC_NOT_EXECUTABLE_'+version+'_'+n).encode()) for n in guard.FILES}
            m={**policy,'entrypoint':'remote-device-proof-v1','files':{k:hashlib.sha256(v).hexdigest() for k,v in data.items()}}
            raw=json.dumps(m,sort_keys=True).encode();h=hashlib.sha256(raw).hexdigest();hashes.append(h)
            p=r/'releases'/h;(p/'server').mkdir(parents=True)
            for n,b in data.items():
                (p/n).parent.mkdir(parents=True,exist_ok=True);(p/n).write_bytes(b)
            (p/'radarserver').chmod(0o755)
            (p/'manifest.json').write_bytes(raw)
            self.sign(key,raw,p/'manifest.ed25519.sig')
        (r/'admin/approved-releases.json').write_text(json.dumps({'schema':1,'manifest_sha256':hashes}))
        return r,*hashes
    def crypto(self,*args):
        p=subprocess.run([str(guard.OPENSSL),*map(str,args)],capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin','OPENSSL_CONF':'/dev/null','LC_ALL':'C'})
        self.assertEqual(p.returncode,0,p.stderr.decode('utf-8','replace'))
    def sign(self,key,raw,out,context=guard.SIGNING_CONTEXT):
        message=self.root/'public-message.bin';message.write_bytes(context+raw)
        self.crypto('pkeyutl','-sign','-inkey',key,'-rawin','-in',message,'-out',out)
    def verify_fixture(self,r,a,b):
        # Windows needs no symlink privilege for policy unit tests. A separate
        # Linux fixture exercises real symlinks and root ownership checks.
        with patch.object(Path,'is_symlink',return_value=True),patch.object(os,'readlink',return_value='releases/'+a):
            return guard.verify(r,a,b,owner=False)
    def test_approved_matching_release_plan(self):
        r,a,b=self.fixture();before={str(p):p.read_bytes() for p in r.rglob('*') if p.is_file()}
        answer=self.verify_fixture(r,a,b)
        self.assertTrue(answer['rollback_allowed']);self.assertFalse(answer['database_rollback']);self.assertTrue(answer['requires_reauthentication'])
        self.assertEqual(before,{str(p):p.read_bytes() for p in r.rglob('*') if p.is_file()})
    def test_unapproved_reject(self):
        r,a,b=self.fixture();(r/'admin/approved-releases.json').write_text('{"schema":1,"manifest_sha256":[]}')
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_tampered_binary_reject(self):
        r,a,b=self.fixture();(r/'releases'/b/'radarserver').write_bytes(b'TAMPERED')
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_tampered_manifest_reject(self):
        r,a,b=self.fixture();p=r/'releases'/b/'manifest.json';p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_policy_mismatch_reject(self):
        r,a,b=self.fixture();p=r/'admin/policy.json';v=json.loads(p.read_text());v['app_id']=8;p.write_text(json.dumps(v))
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_pointer_change_reject(self):
        r,a,b=self.fixture()
        with patch.object(Path,'is_symlink',return_value=True),patch.object(os,'readlink',return_value='releases/'+'0'*64),self.assertRaises(ValueError):guard.verify(r,a,b,owner=False)
    def test_traversal_and_same_release_reject(self):
        r,a,b=self.fixture()
        for x,y in [(a,'../bad'),(a,a),('not-a-hash',b)]:
            with self.assertRaises(ValueError):self.verify_fixture(r,x,y)

    def test_unsigned_approved_reject_both_versions(self):
        r,a,b=self.fixture()
        for h in [a,b]:
            sig=r/'releases'/h/'manifest.ed25519.sig';saved=sig.read_bytes();sig.unlink()
            with self.assertRaises((ValueError,OSError)):self.verify_fixture(r,a,b)
            sig.write_bytes(saved)
    def test_wrong_signing_key_reject(self):
        r,a,b=self.fixture();key=self.root/'other-key.pem';self.crypto('genpkey','-algorithm','ED25519','-out',key)
        p=r/'releases'/b;self.sign(key,(p/'manifest.json').read_bytes(),p/'manifest.ed25519.sig')
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_wrong_context_and_bad_signature_reject(self):
        r,a,b=self.fixture();p=r/'releases'/b;sig=p/'manifest.ed25519.sig'
        self.sign(self.root/'synthetic-signing.pem',(p/'manifest.json').read_bytes(),sig,context=b'')
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
        for raw in [b'',b'x'*63,b'x'*64,b'x'*65]:
            sig.write_bytes(raw)
            with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_rehashed_artifact_and_manifest_without_resign_reject(self):
        r,a,b=self.fixture();p=r/'releases'/b
        changed=b'CHANGED_SYNTHETIC';(p/'radarserver').write_bytes(changed)
        m=json.loads((p/'manifest.json').read_bytes());m['files']['radarserver']=hashlib.sha256(changed).hexdigest()
        raw=json.dumps(m,sort_keys=True).encode();(p/'manifest.json').write_bytes(raw)
        h=hashlib.sha256(raw).hexdigest();p.rename(r/'releases'/h)
        (r/'admin/approved-releases.json').write_text(json.dumps({'schema':1,'manifest_sha256':[a,h]}))
        with self.assertRaises(ValueError):self.verify_fixture(r,a,h)
    def test_pinned_key_mismatch_unconfigured_and_duplicate_trust_reject(self):
        r,a,b=self.fixture();p=r/'admin/release-trust.json'
        for raw in [json.dumps({'schema':1,'algorithm':'Ed25519','public_key_sha256':'0'*64}),json.dumps({'schema':1,'algorithm':'Ed25519','public_key_sha256':None}),'{}','{"schema":1,"schema":1}']:
            p.write_text(raw)
            with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
    def test_first_install_signed_approved_and_no_mutation(self):
        r,a,b=self.fixture();before={str(p):p.read_bytes() for p in r.rglob('*') if p.is_file()}
        answer=guard.verify_first(r,b,owner=False)
        self.assertTrue(answer['first_install_allowed']);self.assertTrue(answer['signature_verified']);self.assertFalse(answer['activated'])
        self.assertEqual(before,{str(p):p.read_bytes() for p in r.rglob('*') if p.is_file()})
    def test_first_install_unsigned_and_unapproved_reject(self):
        r,a,b=self.fixture();sig=r/'releases'/b/'manifest.ed25519.sig';raw=sig.read_bytes();sig.unlink()
        with self.assertRaises((ValueError,OSError)):guard.verify_first(r,b,owner=False)
        sig.write_bytes(raw);(r/'admin/approved-releases.json').write_text('{"schema":1,"manifest_sha256":[]}')
        with self.assertRaises(ValueError):guard.verify_first(r,b,owner=False)
    def test_first_install_existing_file_link_and_dangling_link_reject(self):
        r,a,b=self.fixture();p=r/'current';p.write_text('not-a-pointer')
        with self.assertRaises(ValueError):guard.verify_first(r,b,owner=False)
        p.unlink()
        for dest in ['releases/'+a,'releases/'+'0'*64]:
            p.symlink_to(dest)
            with self.assertRaises(ValueError):guard.verify_first(r,b,owner=False)
            p.unlink()
    def test_signature_symlink_and_missing_crypto_reject(self):
        r,a,b=self.fixture();p=r/'releases'/b/'manifest.ed25519.sig';saved=p.read_bytes();p.unlink();outside=self.root/'public-sig';outside.write_bytes(saved);p.symlink_to(outside)
        with self.assertRaises(ValueError):self.verify_fixture(r,a,b)
        p.unlink();p.write_bytes(saved)
        with patch.object(guard,'OPENSSL',self.root/'missing-openssl'),self.assertRaises(OSError):self.verify_fixture(r,a,b)
    def test_native_root_ownership_and_real_pointer(self):
        r,a,b=self.fixture()
        if os.geteuid()!=0 or '/root/' not in str(r):self.skipTest('explicit root-private Linux fixture required')
        # No mocks: owner checks and all parent directories, real links, actual crypto.
        self.assertTrue(guard.verify_first(r,a)['first_install_allowed'])
        (r/'current').symlink_to('releases/'+a)
        self.assertTrue(guard.verify(r,a,b)['rollback_allowed'])
        p=r/'admin/release-signing-public.der';p.chmod(0o666)
        with self.assertRaises(ValueError):guard.verify(r,a,b)
    def test_openssl_caller_configuration_ignored(self):
        r,a,b=self.fixture()
        with patch.dict(os.environ,{'OPENSSL_CONF':'/nonexistent-caller-config','OPENSSL_MODULES':'/nonexistent-caller-providers'}):
            self.assertTrue(guard.verify_first(r,b,owner=False)['first_install_allowed'])

if __name__=='__main__':unittest.main(verbosity=2)
