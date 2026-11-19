"""Real root-private Linux files/locks/Ed25519; service runner is SYNTHETIC ONLY."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import test_deployment as fixtures
import rollout

class SyntheticRuntime:
    def __init__(self, layout, plan, contents):
        self.layout,self.plan,self.contents=layout,plan,contents
        self.events=[];self.fail=None;self.after_stop=None;self.web=False;self.private=False
    def event(self,name): self.events.append(name);return self.fail!=name
    def probe(self,*args): return self.event('probe')
    def stop_all(self):
        self.web=False;self.private=False;ok=self.event('stop')
        if self.after_stop: callback=self.after_stop;self.after_stop=None;callback()
        return ok
    def validate(self): return self.event('validate')
    def start_private(self): self.private=self.event('start');return self.private
    def ready(self): return self.private and self.event('ready')
    def open_web(self):
        # Public traffic only opens AFTER every config and all three bindings agree.
        assert self.private and 'ready' in self.events
        assert os.readlink(self.layout.root/'current')=='releases/'+self.plan['target']
        for slot,raw in self.contents.items(): assert self.layout.target(slot).read_bytes()==raw
        self.web=self.event('open');return self.web

@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'root-private native Linux fixture required')
class RolloutTests(unittest.TestCase):
    def fixture(self,mode='first-install'):
        h=fixtures.DeploymentTests(methodName='runTest');h.setUp();self.addCleanup(h.doCleanups)
        root,a,b=h.fixture()
        layout=rollout.Layout(root,h.root/'system',h.root/'backends',h.root/'release.lock')
        layout.backends.mkdir()
        backends={}
        for role in ['api','admin']:
            name='gamesense-dataauth-123456789abc-'+role;p=layout.backends/name;p.mkdir()
            for i in range(65): (p/('synthetic-'+str(i))).write_bytes(('backend-'+role+'-'+str(i)).encode())
            backends[role]={'name':name,'tree_sha256':rollout.tree_hash(p)}
        before={};after={};contents={};originals={}
        for slot in rollout.SLOTS:
            p=layout.target(slot);p.parent.mkdir(parents=True,exist_ok=True)
            if slot.startswith('site_'):
                enabled=layout.system/'etc/nginx/sites-enabled'/p.name;enabled.parent.mkdir(parents=True,exist_ok=True);enabled.symlink_to('../sites-available/'+p.name)
            old=('ORIGINAL_'+slot+'\n').encode() if slot.startswith(('site_','pool_')) else None
            if old is not None:p.write_bytes(old);p.chmod(0o640)
            originals[slot]=old;before[slot]=rollout.digest(old) if old is not None else None
            if slot.startswith(('site_','pool_')):
                role='api' if slot=='site_legacy_api' else slot.split('_',1)[1];raw=('REVIEWED '+str(layout.backends/backends[role]['name'])+'\n').encode()
            elif slot=='unit':
                raw=('User=gamesense-radar\nGroup=gamesense-radar\nEnvironment=GUYI_CONFIG_FILE=/etc/gamesense-radar/license-db.php\nExecStart='+str(root)+'/current/radarserver -guyi-project '+str(layout.backends/backends['api']['name'])+' -app-id 7 -mapimg '+str(root)+'/current/maps\n').encode()
            else:raw=('REVIEWED_SYNTHETIC_'+slot+'\n').encode()
            contents[slot]=raw;after[slot]=rollout.digest(raw)
        if mode=='switch':(root/'current').symlink_to('releases/'+a)
        v={'schema':1,'mode':mode,'expected_current':a if mode=='switch' else None,'target':b,'maintenance_stop_all_nginx_and_php_fpm':True,'backends':backends,'before':before,'after':after}
        raw=json.dumps(v,sort_keys=True).encode();digest=rollout.digest(raw)
        p=root/'admin/rollouts'/digest;(p/'files').mkdir(parents=True)
        (p/'plan.json').write_bytes(raw)
        for slot,raw in contents.items():(p/'files'/slot).write_bytes(raw)
        (root/'admin/approved-rollouts.json').write_text(json.dumps({'schema':1,'plan_sha256':[digest]}))
        return layout,digest,v,contents,originals,SyntheticRuntime(layout,v,contents)
    def journal(self,l):
        return json.loads(next((l.root/'admin/transactions').glob('*/journal.json')).read_text())
    def pristine(self,l,old,expected):
        self.assertEqual(rollout.current_pointer(l),expected)
        for slot,raw in old.items():
            p=l.target(slot);self.assertEqual(p.read_bytes() if p.exists() else None,raw)
            if raw is not None:self.assertEqual(p.stat().st_mode&0o777,0o640)
    def test_first_install_coherent_commit(self):
        l,d,v,c,old,r=self.fixture();answer=rollout.transact(l,d,r,apply=True)
        self.assertTrue(answer['activated']);self.assertTrue(r.web)
        self.assertEqual(r.events,['probe','stop','validate','start','ready','open'])
        self.assertEqual(self.journal(l)['state'],'COMMITTED')
        self.assertFalse(answer['database_rollback'])
    def test_existing_signed_release_switch_coherent(self):
        l,d,v,c,old,r=self.fixture('switch');self.assertTrue(rollout.transact(l,d,r,True)['activated'])
        self.assertEqual(rollout.current_pointer(l),v['target'])
    def test_plan_readonly_no_services_or_current(self):
        l,d,v,c,old,r=self.fixture();answer=rollout.transact(l,d,r)
        self.assertTrue(answer['plan_allowed']);self.assertFalse(answer['activated']);self.assertEqual(r.events,[])
        self.pristine(l,old,None);self.assertFalse((l.root/'admin/transactions').exists())
    def test_approval_separate_from_signed_release(self):
        l,d,v,c,old,r=self.fixture();(l.root/'admin/approved-rollouts.json').write_text('{"schema":1,"plan_sha256":[]}')
        with self.assertRaises(ValueError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[]);self.pristine(l,old,None)
    def test_unsigned_business_rejected_before_service_commands(self):
        l,d,v,c,old,r=self.fixture();(l.root/'releases'/v['target']/'manifest.ed25519.sig').unlink()
        with self.assertRaises(OSError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[])
    def test_backend_tamper_before_service_commands(self):
        l,d,v,c,old,r=self.fixture();(l.backends/v['backends']['admin']['name']/'synthetic-0').write_bytes(b'CHANGED')
        with self.assertRaises(ValueError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[])
    def test_configuration_precondition_and_payload_hash(self):
        for which in ['before','after']:
            with self.subTest(which=which):
                l,d,v,c,old,r=self.fixture()
                p=l.target('site_admin') if which=='before' else l.root/'admin/rollouts'/d/'files/site_admin'
                p.write_bytes(b'CHANGED')
                with self.assertRaises(ValueError):rollout.transact(l,d,r,True)
                self.assertEqual(r.events,[])
    def test_symlink_config_rejected(self):
        l,d,v,c,old,r=self.fixture();p=l.target('site_api');other=p.with_name('other');p.rename(other);p.symlink_to(other)
        with self.assertRaises(ValueError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[])
    def test_enabled_site_must_point_to_reviewed_config(self):
        l,d,v,c,old,r=self.fixture();p=l.system/'etc/nginx/sites-enabled/guyi-access';p.unlink();p.symlink_to('../sites-available/unreviewed')
        with self.assertRaises(ValueError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[])
    def test_real_lock_conflict_rejects_second_writer(self):
        l,d,v,c,old,r=self.fixture()
        with rollout.locked(l),self.assertRaises(BlockingIOError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[])
    def test_hostile_lock_symlink_denied(self):
        l,d,v,c,old,r=self.fixture();l.lock.symlink_to(l.root/'admin/policy.json')
        with self.assertRaises(OSError):rollout.transact(l,d,r,True)
        self.assertEqual(r.events,[])
    def test_in_lock_revalidation_after_stop(self):
        l,d,v,c,old,r=self.fixture()
        r.after_stop=lambda:(l.root/'admin/approved-rollouts.json').write_text('{"schema":1,"plan_sha256":[]}')
        with self.assertRaises(RuntimeError):rollout.transact(l,d,r,True)
        self.assertFalse(r.web);self.pristine(l,old,None)
        self.assertEqual(self.journal(l)['state'],'FAILED_CLOSED')
    def test_each_runtime_failure_restores_files_but_never_legacy_services(self):
        for mode in ['first-install','switch']:
            for failure in ['validate','start','ready','open']:
                with self.subTest(mode=mode,failure=failure):
                    l,d,v,c,old,r=self.fixture(mode);r.fail=failure
                    with self.assertRaises(RuntimeError):rollout.transact(l,d,r,True)
                    self.pristine(l,old,v['expected_current']);self.assertFalse(r.web);self.assertFalse(r.private)
                    j=self.journal(l);self.assertEqual(j['state'],'FAILED_CLOSED');self.assertTrue(j['configuration_restored']);self.assertFalse(j['legacy_services_restarted'])
    def test_partial_file_write_failure_restores_both_backends(self):
        l,d,v,c,old,r=self.fixture();original=rollout.replace_file;once=[True]
        def failing(p,*args):
            if p==l.target('pool_api') and once[0]:once[0]=False;raise OSError('synthetic disk failure')
            return original(p,*args)
        with patch.object(rollout,'replace_file',side_effect=failing),self.assertRaises(RuntimeError):rollout.transact(l,d,r,True)
        self.pristine(l,old,None);self.assertFalse(r.web);self.assertEqual(self.journal(l)['state'],'FAILED_CLOSED')
    def test_external_config_edit_not_overwritten_on_failure(self):
        l,d,v,c,old,r=self.fixture()
        def bad_validate():l.target('site_admin').write_bytes(b'EXTERNAL_EDIT');return False
        r.validate=bad_validate
        with self.assertRaises(RuntimeError):rollout.transact(l,d,r,True)
        self.assertEqual(l.target('site_admin').read_bytes(),b'EXTERNAL_EDIT');self.assertFalse(r.web)
        self.assertEqual(self.journal(l)['state'],'MANUAL_RECOVERY_REQUIRED')
    def test_probe_failure_no_configuration_or_service_mutation(self):
        l,d,v,c,old,r=self.fixture();r.fail='probe'
        with self.assertRaises(ValueError):rollout.transact(l,d,r,True)
        self.pristine(l,old,None);self.assertEqual(r.events,['probe'])
    def test_cannot_confirm_stop_no_configuration_restore_over_live_services(self):
        l,d,v,c,old,r=self.fixture();r.fail='stop'
        with self.assertRaises(RuntimeError):rollout.transact(l,d,r,True)
        self.pristine(l,old,None);self.assertEqual(self.journal(l)['state'],'MANUAL_RECOVERY_REQUIRED')
    def test_actual_process_death_leaves_wal_and_blocks_retry(self):
        l,d,v,c,old,r=self.fixture();pid=os.fork()
        if pid==0:
            r.validate=lambda:os._exit(73)
            rollout.transact(l,d,r,True);os._exit(74)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
        self.assertEqual(self.journal(l)['state'],'CURRENT_SET')
        self.assertFalse(r.web)  # No real service runner exists in either process.
        with self.assertRaisesRegex(ValueError,'manual recovery'):rollout.transact(l,d,r,True)
    def test_cli_no_path_or_owner_overrides(self):
        p=subprocess.run(['/usr/bin/python3','-B',str(Path(rollout.__file__)),'--root','/tmp','--apply'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('ROLLOUT_DENIED',p.stderr)
    def test_legacy_data_only_apply_disabled(self):
        p=subprocess.run(['/bin/sh',str(Path(rollout.__file__).parent/'templates/rollback-release.sh.in'),'a'*64,'b'*64,'--apply'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('COHERENT_ROLLOUT_REQUIRED',p.stderr)

if __name__=='__main__': unittest.main(verbosity=2)
