#!/usr/bin/env python3
"""Build three obfuscated v16 EXEs and preserve all matching runtime-template assets."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import zipfile
import build_protected as core

PREFIX='gamesense-client/'
EXES=('capture.exe','gamesense.exe','设备凭据修复.exe')
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--go',required=True);p.add_argument('--garble',required=True)
 p.add_argument('--runtime-template',type=Path,required=True)
 p.add_argument('--origin-source-sha256',required=True);p.add_argument('--source-sha256',required=True);p.add_argument('--out',type=Path,required=True)
 a=p.parse_args()
 if not re.fullmatch('[0-9a-f]{64}',a.source_sha256):raise ValueError('invalid source fingerprint')
 if a.out.exists():raise ValueError('fresh output required')
 with zipfile.ZipFile(a.runtime_template) as z:
  if z.testzip() is not None:raise ValueError('runtime template integrity error')
  contents={n:z.read(n) for n in z.namelist() if not n.endswith('/')}
 for name in contents:
  if not name.startswith(PREFIX) or '..' in Path(name).parts or '\\' in name:raise ValueError('unsafe runtime path')
 receipt=json.loads(contents[PREFIX+'DEPLOYMENT-RECEIPT.json'])
 if receipt.get('this_client_source_sha256')!=a.origin_source_sha256:raise ValueError('source and runtime-template receipt do not match')
 public=core.public_configuration_files(core.ROOT/'dist')
 for name,raw in public.items():
  if contents.get(PREFIX+name)!=raw:raise ValueError('template public configuration mismatch')
 a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False)
 private=a.out/'.build-private'
 args=core.parser().parse_args(['--unsigned','--go',a.go,'--garble',a.garble,'--out',str(private)])
 with contextlib.redirect_stdout(io.StringIO()):core.build(args)
 env=os.environ.copy();env.update(core.plan(args)['environment'])
 env['PATH']=str(Path(args.go).parent)+os.pathsep+env.get('PATH','');env['GOENV']='off'
 env['GARBLE_CACHE']=str(private/'.private-garble-cache')
 repair=private/EXES[2]
 command=[args.garble,'-literals','-tiny','-seed=random','build','-mod=vendor','-trimpath',
          '-ldflags=-s -w -H=windowsgui -X main.defaultDeviceRepairMode=true','-o',str(repair),'./cmd/collector']
 core.run(command,env,private/'BUILD-PRIVATE.jsonl')
 files={'capture.exe':private/'capture.exe','gamesense.exe':private/'CS2雷达.exe',EXES[2]:repair}
 for name,path in files.items():contents[PREFIX+name]=path.read_bytes()
 metadata={'schema':1,'source_input_sha256':a.source_sha256,'origin_v16_source_sha256':a.origin_source_sha256,'approved_ui':'20261101-v3','runtime_template_sha256':sha(a.runtime_template.read_bytes()),
           'garble':'v0.18.0','flags':['-literals','-tiny','-seed=random'],
           'controlflow_function':'authorizeCaptureWithCard','controlflow_parameters':'block_splits=2 junk_jumps=1 flatten_passes=1',
           'authenticode_signed':False,'exe_sha256':{n:sha(contents[PREFIX+n]) for n in EXES},
           'asset_policy':'all original non-EXE assets preserved; receipt and checksum table updated',
           'server_deployed':False,'cloud_updater_implemented':False}
 contents[PREFIX+'OBFUSCATION.json']=(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
 receipt['obfuscation_build']=metadata
 contents[PREFIX+'DEPLOYMENT-RECEIPT.json']=(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
 sums=''.join(sha(raw)+'  '+name[len(PREFIX):]+'\n' for name,raw in sorted(contents.items()) if name!=PREFIX+'SHA256SUMS.txt')
 contents[PREFIX+'SHA256SUMS.txt']=sums.encode('utf-8')
 for name,raw in contents.items():
  path=a.out/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
 bundle=a.out/'gamesense-client-Windows-x64-20261101-UIv3-garble.zip'
 with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED) as z:
  for name,raw in sorted(contents.items()):z.writestr(name,raw)
 print(json.dumps({'bundle':str(bundle),'sha256':sha(bundle.read_bytes()),'exe_sha256':metadata['exe_sha256'],
                   'files':len(contents),'signed':False},ensure_ascii=False))
 return 0

if __name__=='__main__':
 try:sys.exit(main())
 except (ValueError,OSError,RuntimeError,zipfile.BadZipFile) as e:print(str(e),file=sys.stderr);sys.exit(1)
