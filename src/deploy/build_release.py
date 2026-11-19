#!/usr/bin/env python3
"""Offline unsigned candidate assembly. Never signs, approves, uploads or starts."""
import argparse,hashlib,json,os,stat
from pathlib import Path
import release_check as guard
import render
SOURCE=Path(__file__).resolve().parent.parent
def build(binary,config,out):
    c=render.load_config(config);out=Path(out)
    if os.path.lexists(out):raise ValueError('fresh output required')
    paths={'radarserver':Path(binary)}
    paths.update({n:SOURCE/n for n in guard.CORE_FILES if n!='radarserver'})
    paths.update({n:SOURCE/'dist'/n for n in guard.MAP_FILES})
    data={}
    for n,p in paths.items():
        if not stat.S_ISREG(p.lstat().st_mode) or any(q.is_symlink() for q in p.parents):raise ValueError('untrusted input')
        raw=p.read_bytes()
        if not raw or len(raw)>64*1024*1024:raise ValueError('input size')
        data[n]=raw
    if set(data)!=guard.FILES:raise ValueError('closed release set')
    m={k:c[k] for k in ['schema','security_epoch','public_origin','app_id']}
    m.update(entrypoint='remote-device-proof-v1',files={n:hashlib.sha256(b).hexdigest() for n,b in sorted(data.items())})
    raw=(json.dumps(m,sort_keys=True,indent=2)+'\n').encode()
    if len(raw)>16384:raise ValueError('manifest bound')
    out.mkdir(mode=0o755 if os.name=='nt' else 0o700)
    for n,b in data.items():
        p=out/n;p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb') as f:f.write(b)
        p.chmod(0o750 if n=='radarserver' else 0o640)
    (out/'manifest.json').write_bytes(raw)
    return {'manifest_sha256':hashlib.sha256(raw).hexdigest(),'files':len(data),'maps':len([n for n in data if n.endswith('/overview.png')]),'signed':False,'approved':False,'activated':False}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--binary',required=True);a.add_argument('--config',required=True);a.add_argument('--out',required=True);v=a.parse_args()
    print(json.dumps(build(v.binary,v.config,v.out)))
