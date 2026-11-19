#!/usr/bin/env python3
"""Root-only, separately approved maintenance transaction. No credentials or DB DDL."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

import release_check as guard

SLOTS = {
    'site_api': 'etc/nginx/sites-available/guyi-ip-api',
    'site_legacy_api': 'etc/nginx/sites-available/guyi-access',
    'site_admin': 'etc/nginx/sites-available/guyi-tunnel-admin',
    'pool_api': 'etc/php/8.2/fpm/pool.d/guyi-access.conf',
    'pool_admin': 'etc/php/8.2/fpm/pool.d/guyi-http-admin.conf',
    'unit': 'etc/systemd/system/gamesense-radar.service',
    'upstream': 'etc/nginx/snippets/gamesense-radar-upstream.conf',
    'locations': 'etc/nginx/snippets/gamesense-radar-locations.conf',
}
ROOT = Path('/opt/gamesense-radar')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'OPENSSL_CONF': '/dev/null', 'PYTHONDONTWRITEBYTECODE': '1'}

def digest(raw): return hashlib.sha256(raw).hexdigest()

class Layout:
    # Alternate filesystem roots are a LIBRARY fixture seam, never CLI options.
    def __init__(self, root=ROOT, system=Path('/'), backends=Path('/opt/guyi-access/releases'), lock=Path('/run/lock/gamesense-radar-release.lock')):
        self.root, self.system, self.backends, self.lock = map(Path, (root, system, backends, lock))
    def target(self, slot): return self.system / SLOTS[slot]

def trusted_parents(p):
    for q in (p,) + tuple(p.parents): guard.directory(q, True)

def tree_hash(p):
    trusted_parents(p)
    files = {}
    for q in sorted(p.rglob('*')):
        if q.is_dir() and not q.is_symlink(): guard.directory(q, True)
        else: files[q.relative_to(p).as_posix()] = digest(guard.regular(q, True, 8*1024*1024))
    if len(files) != 65: raise ValueError('exact prepared backend file count required')
    return digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())

@contextmanager
def locked(layout):
    import fcntl
    p = layout.lock
    # /run/lock may be root-owned sticky 1777; an existing hostile lock is denied.
    s = p.parent.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or (s.st_mode & 0o022 and not s.st_mode & stat.S_ISVTX):
        raise ValueError('untrusted lock directory')
    for q in p.parent.parents: guard.directory(q, True)
    fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022 or s.st_nlink != 1:
            raise ValueError('untrusted lock file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)  # Persistent lock inode: never unlink a shared lock.

def sync_dir(p):
    fd=os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def replace_file(p, raw, mode=0o644, gid=0):
    trusted_parents(p.parent)
    tmp = p.with_name('.gs-rollout-'+uuid.uuid4().hex)
    try:
        fd=os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd,'wb') as f:
            os.fchown(f.fileno(),0,gid);os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p);sync_dir(p.parent)
    finally:
        if os.path.lexists(tmp): tmp.unlink()

def metadata(p, value): replace_file(p, (json.dumps(value,sort_keys=True)+'\n').encode(),0o600)

def current_pointer(layout):
    p=layout.root/'current'
    if not os.path.lexists(p): return None
    if not p.is_symlink(): raise ValueError('untrusted current')
    value=os.readlink(p)
    if not re.fullmatch(r'releases/[a-f0-9]{64}',value): raise ValueError('untrusted current')
    return value[9:]

def set_pointer(layout, target):
    p=layout.root/'current'
    if target is None:
        if os.path.lexists(p):
            if not p.is_symlink(): raise ValueError('untrusted current during restore')
            p.unlink();sync_dir(p.parent)
        return
    tmp=layout.root/('.gs-current-'+uuid.uuid4().hex)
    try:
        tmp.symlink_to('releases/'+target);os.replace(tmp,p);sync_dir(p.parent)
    finally:
        if os.path.lexists(tmp): tmp.unlink()

def load_plan(layout, plan_sha):
    if not isinstance(plan_sha,str) or not guard.SHA.fullmatch(plan_sha): raise ValueError('plan hash')
    trusted_parents(layout.root/'admin/rollouts'/plan_sha)
    p=layout.root/'admin/rollouts'/plan_sha
    raw=guard.regular(p/'plan.json',True,16384)
    if digest(raw)!=plan_sha: raise ValueError('plan integrity')
    approved=guard.document(guard.regular(layout.root/'admin/approved-rollouts.json',True,16384))
    if not isinstance(approved,dict) or set(approved)!={'schema','plan_sha256'} or type(approved['schema']) is not int or approved['schema']!=1 or not isinstance(approved['plan_sha256'],list) or len(approved['plan_sha256'])>64 or any(not isinstance(x,str) or not guard.SHA.fullmatch(x) for x in approved['plan_sha256']) or plan_sha not in approved['plan_sha256']:
        raise ValueError('maintenance rollout not separately approved')
    v=guard.document(raw)
    fields={'schema','mode','expected_current','target','maintenance_stop_all_nginx_and_php_fpm','backends','before','after'}
    if not isinstance(v,dict) or set(v)!=fields or type(v['schema']) is not int or v['schema']!=1 or v['mode'] not in ('first-install','switch') or v['maintenance_stop_all_nginx_and_php_fpm'] is not True:
        raise ValueError('maintenance plan schema/scope')
    if not isinstance(v['target'],str) or not guard.SHA.fullmatch(v['target']): raise ValueError('target hash')
    if v['mode']=='first-install':
        if v['expected_current'] is not None: raise ValueError('first install has no predecessor')
        guard.verify_first(layout.root,v['target'])
    else: guard.verify(layout.root,v['expected_current'],v['target'])
    if current_pointer(layout)!=v['expected_current']: raise ValueError('current changed')
    if not isinstance(v['backends'],dict) or set(v['backends'])!={'api','admin'}: raise ValueError('both backends required')
    roots={}
    for name,b in v['backends'].items():
        if not isinstance(b,dict) or set(b)!={'name','tree_sha256'} or not isinstance(b['name'],str) or not re.fullmatch(r'gamesense-dataauth-[a-f0-9]{12}-'+name,b['name']) or not isinstance(b['tree_sha256'],str) or not guard.SHA.fullmatch(b['tree_sha256']): raise ValueError('backend binding')
        roots[name]=layout.backends/b['name']
        if tree_hash(roots[name])!=b['tree_sha256']: raise ValueError('backend changed')
    if not all(isinstance(v[k],dict) and set(v[k])==set(SLOTS) for k in ['before','after']): raise ValueError('exact configuration slots required')
    contents={};snapshots={}
    trusted_parents(p/'files')
    for slot in ['site_api','site_legacy_api','site_admin']:
        target=layout.target(slot)
        enabled=layout.system/'etc/nginx/sites-enabled'/target.name
        trusted_parents(enabled.parent)
        s=enabled.lstat()
        if not stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or os.readlink(enabled) not in [str(target),'../sites-available/'+target.name]:
            raise ValueError('active site is not bound to reviewed config')
    for slot in SLOTS:
        before,after=v['before'][slot],v['after'][slot]
        if before is not None and (not isinstance(before,str) or not guard.SHA.fullmatch(before)): raise ValueError('before hash')
        if not isinstance(after,str) or not guard.SHA.fullmatch(after): raise ValueError('after hash')
        target=layout.target(slot);trusted_parents(target.parent)
        old=guard.regular(target,True,256*1024) if os.path.lexists(target) else None
        if (digest(old) if old is not None else None)!=before: raise ValueError('configuration changed')
        content=guard.regular(p/'files'/slot,True,256*1024)
        if digest(content)!=after: raise ValueError('configuration payload changed')
        contents[slot]=content
        snapshots[slot]={'raw':old,'mode':stat.S_IMODE(target.stat().st_mode) if old is not None else None,'gid':target.stat().st_gid if old is not None else None}
    # Root-approved exact byte payloads still must bind BOTH prepared backends and
    # the fixed, least-privilege unit entrypoint. Parsers run only while web is off.
    for name in ['api','admin']:
        for slot in ['site_'+name,'pool_'+name]:
            if str(roots[name]).encode() not in contents[slot]: raise ValueError('backend/config mismatch')
    if str(roots['api']).encode() not in contents['site_legacy_api']: raise ValueError('legacy API site not bound to reviewed backend')
    required=['User=gamesense-radar\n','Group=gamesense-radar\n','ExecStart='+str(layout.root)+'/current/radarserver ', '-guyi-project '+str(roots['api'])+' ', 'Environment=GUYI_CONFIG_FILE=/etc/gamesense-radar/license-db.php\n']
    if any(s.encode() not in contents['unit'] for s in required): raise ValueError('service/config mismatch')
    import shlex
    starts=[line[len('ExecStart='):] for line in contents['unit'].decode().splitlines() if line.startswith('ExecStart=')]
    if len(starts)!=1: raise ValueError('one reviewed service command required')
    args=shlex.split(starts[0])
    if args.count('-mapimg')!=1 or args.index('-mapimg')+1>=len(args) or args[args.index('-mapimg')+1]!=str(layout.root)+'/current/maps':
        raise ValueError('signed map asset directory not bound')
    return v,contents,snapshots,roots

class Runtime:
    """Only fixed executables/argv; no shell, plan-supplied commands or PATH lookup."""
    def call(self,args):
        p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=45,env=ENV,cwd='/')
        return p.returncode==0
    def stop_all(self):
        # Stop web first; a partially applied generation must never receive traffic.
        ok=self.call(['/usr/bin/systemctl','stop','nginx.service','php8.2-fpm.service'])
        data=self.call(['/usr/bin/systemctl','stop','gamesense-radar.service'])
        if not data:
            p=subprocess.run(['/usr/bin/systemctl','show','gamesense-radar.service','-p','LoadState','--value'],capture_output=True,timeout=10,env=ENV,cwd='/')
            data=p.returncode==0 and p.stdout.strip()==b'not-found'
        port=subprocess.run(['/usr/bin/ss','-H','-lnt','( sport = :18081 )'],capture_output=True,timeout=5,env=ENV,cwd='/')
        return ok and data and port.returncode==0 and not port.stdout.strip()
    def probe(self,layout,v,roots):
        for name in ['api','admin']:
            args=['/usr/sbin/runuser','-u','gamesense-radar','--','/usr/bin/env','GUYI_CONFIG_FILE=/etc/gamesense-radar/license-db.php','PHP_INI_SCAN_DIR=/etc/php/8.2/cli/conf.d','/usr/bin/php8.2',str(layout.root/'releases'/v['target']/'server/license-authority-cli.php'),str(roots[name]),'1']
            policy=guard.configuration(layout.root,True)[0];args[-1]=str(policy['app_id'])
            p=subprocess.run(args,input=b'{"op":"probe"}',capture_output=True,timeout=10,env=ENV,cwd='/')
            if p.returncode or p.stderr or json.loads(p.stdout)!={'ok':True,'identity':{}}: return False
        return True
    def validate(self):
        return self.call(['/usr/sbin/nginx','-t']) and self.call(['/usr/sbin/php-fpm8.2','-t']) and self.call(['/usr/bin/systemctl','daemon-reload'])
    def start_private(self):
        return self.call(['/usr/bin/systemctl','start','php8.2-fpm.service']) and self.call(['/usr/bin/systemctl','start','gamesense-radar.service'])
    def ready(self):
        for _ in range(5):
            if self.call(['/usr/bin/curl','--noproxy','*','--fail','--silent','--max-time','1','http://127.0.0.1:18081/health']): return True
            time.sleep(1)
        return False
    def open_web(self): return self.call(['/usr/bin/systemctl','start','nginx.service'])

def transact(layout, plan_sha, runtime=None, apply=False):
    if runtime is None: runtime=Runtime()
    # Even planning holds the same release lock and validates inside it; an
    # earlier plan result is not a write authorization or a cached validation.
    with locked(layout):
        transactions=layout.root/'admin/transactions'
        if transactions.exists():
            trusted_parents(transactions)
            for d in transactions.iterdir():
                guard.directory(d,True)
                j=guard.document(guard.regular(d/'journal.json',True,16384))
                if j.get('state') not in ['COMMITTED','FAILED_CLOSED']: raise ValueError('incomplete transaction: manual recovery required')
        v,contents,snapshots,roots=load_plan(layout,plan_sha)
        if not apply: return {'plan_allowed':True,'activated':False,'requires_maintenance':True,'target':v['target']}
        if not runtime.probe(layout,v,roots): raise ValueError('actual identity/backend probe failed')
        if not transactions.exists(): transactions.mkdir(mode=0o700)
        tx=transactions/uuid.uuid4().hex;tx.mkdir(mode=0o700)
        j={'schema':1,'plan_sha256':plan_sha,'target':v['target'],'expected_current':v['expected_current'],'state':'PREPARED','before':{slot:{'sha256':v['before'][slot],'mode':s['mode'],'gid':s['gid']} for slot,s in snapshots.items()}}
        for slot,s in snapshots.items():
            if s['raw'] is not None: replace_file(tx/slot,s['raw'],0o600)
        def state(value): j['state']=value;metadata(tx/'journal.json',j)
        state('PREPARED');mutated=False;quiesced=False
        try:
            if not runtime.stop_all(): raise RuntimeError('quiesce failed')
            quiesced=True;state('QUIESCED')
            # Recheck under lock AFTER quiescence, before the first configuration write.
            load_plan(layout,plan_sha)
            mutated=True
            for slot,raw in contents.items(): replace_file(layout.target(slot),raw)
            state('CONFIGS_INSTALLED');set_pointer(layout,v['target']);state('CURRENT_SET')
            if not runtime.validate(): raise RuntimeError('configuration parsers failed')
            state('CONFIGS_VALIDATED')
            if not runtime.start_private() or not runtime.ready(): raise RuntimeError('private readiness failed')
            state('PRIVATE_READY')
            if not runtime.open_web(): raise RuntimeError('web start failed')
            state('COMMITTED')
            return {'activated':True,'target':v['target'],'transaction':tx.name,'requires_reauthentication':True,'database_rollback':False}
        except BaseException:
            # Includes signals translated to KeyboardInterrupt/SystemExit. SIGKILL
            # cannot run cleanup; a nonterminal WAL blocks another apply for review.
            stopped=False
            try: stopped=runtime.stop_all()
            except BaseException: pass
            restored=not mutated
            try:
                if mutated and stopped:
                    # Do not overwrite an independently edited configuration/current.
                    if current_pointer(layout) not in [v['expected_current'],v['target']]: raise ValueError('external pointer change')
                    for slot in SLOTS:
                        p=layout.target(slot);raw=guard.regular(p,True,256*1024) if os.path.lexists(p) else None
                        if (digest(raw) if raw is not None else None) not in [v['before'][slot],v['after'][slot]]: raise ValueError('external config change')
                    for slot,s in snapshots.items():
                        p=layout.target(slot)
                        if s['raw'] is None:
                            if os.path.lexists(p): p.unlink();sync_dir(p.parent)
                        else: replace_file(p,s['raw'],s['mode'],s['gid'])
                    set_pointer(layout,v['expected_current']);restored=True
            except BaseException: restored=False
            j.update(services_confirmed_stopped=stopped,configuration_restored=restored,legacy_services_restarted=False)
            state('FAILED_CLOSED' if stopped and restored else 'MANUAL_RECOVERY_REQUIRED')
            raise RuntimeError('ROLLOUT_FAILED_CLOSED: inspect root-private transaction '+tx.name) from None

def main():
    # Keep plan/apply as explicit option flags, not optional behavior defaults.
    argv=sys.argv[1:]
    try:
        if len(argv)!=2 or argv[1] not in ['--plan','--apply'] or os.name!='posix' or os.geteuid()!=0: raise ValueError('Linux administrator and explicit action required')
        answer=transact(Layout(),argv[0],apply=argv[1]=='--apply')
        print(json.dumps(answer));return 0
    except (OSError,ValueError,RuntimeError,TypeError,KeyError,subprocess.SubprocessError):
        print('ROLLOUT_DENIED_OR_STOPPED: no implicit approval, legacy fallback or database restore; inspect root-private journal',file=sys.stderr);return 2

if __name__=='__main__': raise SystemExit(main())
