"""Local filesystem/GD/sodium fixtures; no production DB, network or services.
Windows crypto fixture uses real sodium, not the Linux OpenSSL/UID sandbox.
"""
import argparse,base64,hashlib,importlib.util,json,os,shutil,subprocess,tempfile,unittest,uuid
from pathlib import Path
from unittest.mock import patch
import release_check as guard
import render,build_release
SOURCE=Path(__file__).resolve().parent.parent
PHP=None
RECORDS=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def run(args,raw=b''):
    p=subprocess.run(list(map(str,args)),input=raw,capture_output=True)
    RECORDS.append({'command':list(map(str,args)),'stdin':raw.decode('utf-8'),'stdout':p.stdout.decode('utf-8','replace'),'stderr':p.stderr.decode('utf-8','replace'),'exit':p.returncode})
    return p
def php(code,raw=b''):
    p=run([PHP,'-n','-d','extension_dir='+str(Path(PHP).parent/'ext'),'-d','extension=sodium','-r',code],raw)
    if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
    return p.stdout
def sign(raw):
    v=json.loads(php('$m=base64_decode(stream_get_contents(STDIN));$k=sodium_crypto_sign_keypair();echo json_encode([base64_encode(sodium_crypto_sign_publickey($k)),base64_encode(sodium_crypto_sign_detached($m,sodium_crypto_sign_secretkey($k)))]);',base64.b64encode(guard.SIGNING_CONTEXT+raw)))
    return bytes.fromhex('302a300506032b6570032100')+base64.b64decode(v[0]),base64.b64decode(v[1])
def verify(raw,key,sig):
    v=[base64.b64encode(x).decode() for x in [guard.SIGNING_CONTEXT+raw,key[-32:],sig]]
    out=php('$a=json_decode(stream_get_contents(STDIN),true);echo sodium_crypto_sign_verify_detached(base64_decode($a[2]),base64_decode($a[0]),base64_decode($a[1]))?"yes":"no";',json.dumps(v).encode())
    if out!=b'yes':raise ValueError('invalid fixture Ed25519 signature')
class PersistenceTests(unittest.TestCase):
    def setUp(self):
        base=Path(os.environ.get('GAMESENSE_FIXTURE_ROOT',tempfile.gettempdir())).resolve()
        base.mkdir(parents=True,exist_ok=True)
        owned=base/('gamesense-persistence-'+uuid.uuid4().hex);owned.mkdir(mode=0o755)
        def cleanup():
            assert not owned.is_symlink() and owned.resolve().parent==base
            shutil.rmtree(owned)
        self.addCleanup(cleanup);self.root=owned
        self.config={'schema':1,'security_epoch':1,'app_id':7,'public_origin':'https://118.25.176.85','guyi_project':'/opt/guyi-access/releases/gamesense-dataauth-123456789abc-api','php_binary':'/usr/bin/php8.2'}
        self.cfg=self.root/'config.json';self.cfg.write_text(json.dumps(self.config))
    def fixture(self):
        r=self.root/'runtime';(r/'admin').mkdir(parents=True);(r/'releases').mkdir()
        b=self.root/'synthetic-binary';b.write_bytes(b'SYNTHETIC_NEVER_EXECUTED')
        out=self.root/'unsigned';answer=build_release.build(b,self.cfg,out)
        self.assertFalse(answer['signed']);self.assertEqual(answer['files'],40);self.assertEqual(answer['maps'],17)
        raw=(out/'manifest.json').read_bytes();digest=sha(raw);p=r/'releases'/digest;out.rename(p)
        key,sig=sign(raw);(p/'manifest.ed25519.sig').write_bytes(sig)
        policy={k:self.config[k] for k in ['schema','security_epoch','app_id','public_origin']}
        for n,v in [('policy.json',policy),('approved-releases.json',{'schema':1,'manifest_sha256':[digest]}),('release-trust.json',{'schema':1,'algorithm':'Ed25519','public_key_sha256':sha(key)})]:(r/'admin'/n).write_text(json.dumps(v))
        (r/'admin/release-signing-public.der').write_bytes(key)
        return r,p,digest
    def accepted(self,r,d):
        with patch.object(guard,'signature',verify):return guard.verify_first(r,d,owner=False)
    def test_signed40_maps_and_each_rejection(self):
        base=self.root
        for failure in ['none','map-tamper','missing','extra','license','signature','approval']:
            with self.subTest(failure=failure):
                self.root=base/failure;self.root.mkdir();self.cfg=self.root/'config.json';self.cfg.write_text(json.dumps(self.config))
                r,p,d=self.fixture()
                if failure=='map-tamper':(p/'maps/de_train/overview.png').write_bytes(b'TAMPERED')
                if failure=='missing':(p/'maps/de_mirage/overview.png').unlink()
                if failure=='extra':(p/'maps/unsigned.php').write_bytes(b'extra')
                if failure=='license':(p/'maps/de_ancient/LICENSE').write_bytes(b'tamper')
                if failure=='signature':(p/'manifest.ed25519.sig').write_bytes(bytes(64))
                if failure=='approval':(r/'admin/approved-releases.json').write_text('{"schema":1,"manifest_sha256":[]}')
                if failure=='none':self.assertTrue(self.accepted(r,d)['signature_verified'])
                else:
                    with self.assertRaises(ValueError):self.accepted(r,d)
    def test_builder_no_overwrite(self):
        b=self.root/'binary';b.write_bytes(b'fixture');out=self.root/'existing';out.mkdir();(out/'keep').write_bytes(b'pristine')
        with self.assertRaises(ValueError):build_release.build(b,self.cfg,out)
        self.assertEqual((out/'keep').read_bytes(),b'pristine')
    def test_old_three_file_manifest_is_not_approved_by_new_policy(self):
        r,p,d=self.fixture()
        m=json.loads((p/'manifest.json').read_text())
        m['files']={k:v for k,v in m['files'].items() if k in guard.CORE_FILES}
        raw=(json.dumps(m,sort_keys=True)+'\n').encode();new=sha(raw);dest=p.with_name(new);p.rename(dest)
        key,sig=sign(raw);(dest/'manifest.json').write_bytes(raw);(dest/'manifest.ed25519.sig').write_bytes(sig)
        (r/'admin/release-signing-public.der').write_bytes(key)
        (r/'admin/release-trust.json').write_text(json.dumps({'schema':1,'algorithm':'Ed25519','public_key_sha256':sha(key)}))
        (r/'admin/approved-releases.json').write_text(json.dumps({'schema':1,'manifest_sha256':[new]}))
        with self.assertRaises(ValueError):self.accepted(r,new)
    def test_render_wiring_and_empty_approval(self):
        out=self.root/'rendered';files=render.render(self.cfg,out);self.assertEqual(len(files),12)
        self.assertIn('-mapimg /opt/gamesense-radar/current/maps',(out/'gamesense-radar.service').read_text())
        text=(out/'gamesense-avatar-locations.conf').read_text()
        self.assertIn('avatar_[0-9a-f]{32}',text)
        self.assertEqual(sum(line.startswith('location ~ "^') and line.endswith('" {') for line in text.splitlines()),2);self.assertIn('location /media/avatars/ { return 404; }',text)
        self.assertNotIn('fastcgi_pass',text);self.assertNotIn('autoindex on',text)
        self.assertEqual(json.loads((out/'approved-releases.json').read_text())['manifest_sha256'],[])
    def backend(self,role):
        spec=importlib.util.spec_from_file_location('avatar_prepare',SOURCE/'server/prepare_avatar_backend.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        old=self.root/('backend-'+role);(old/'app/Security').mkdir(parents=True);(old/'app/Admin').mkdir()
        f=SOURCE/'server/tests/fixtures/avatar'
        for a,b in [(f/('Admin-'+role+'.php'),old/'app/Security/Admin.php'),(f/'Protocol.php',old/'app/Security/Protocol.php'),(f/'Actions.php',old/'app/Admin/Actions.php')]:b.write_bytes(a.read_bytes())
        before={str(x.relative_to(old)):x.read_bytes() for x in old.rglob('*') if x.is_file()}
        new=self.root/('new-'+role);m.prepare(old,new);self.assertEqual(before,{str(x.relative_to(old)):x.read_bytes() for x in old.rglob('*') if x.is_file()})
        return m,old,new
    def test_both_exact_backend_variants_php_gd_and_transactions(self):
        for role in ['api','admin']:
            m,old,new=self.backend(role)
            for rel in ['app/Security/Admin.php','app/Admin/Actions.php']:
                q=run([PHP,'-n','-l',new/rel]);self.assertEqual(q.returncode,0,q.stdout+q.stderr)
            directory=self.root/('avatars-'+role);directory.mkdir()
            q=run([PHP,'-n','-d','extension_dir='+str(Path(PHP).parent/'ext'),'-d','extension=gd',SOURCE/'server/tests/avatar_fixture.php',new,directory])
            self.assertEqual(q.returncode,0,q.stdout+q.stderr);result=json.loads(q.stdout)
            self.assertTrue(result['ok']);self.assertFalse(result['production_db_used']);self.assertTrue(result['uncertain_commit_retains_png'])
            with self.assertRaises(ValueError):m.prepare(old,new)
    def test_unknown_backend_rejected(self):
        m,old,new=self.backend('api');(old/'app/Admin/Actions.php').write_bytes(b'unknown')
        with self.assertRaises(ValueError):m.prepare(old,self.root/'rejected')
        self.assertFalse((self.root/'rejected').exists())
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--php',required=True);v=a.parse_args();PHP=v.php
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PersistenceTests))
    print('PERSISTENCE_NATIVE_RECORDS='+json.dumps(RECORDS))
    raise SystemExit(0 if result.wasSuccessful() else 1)
