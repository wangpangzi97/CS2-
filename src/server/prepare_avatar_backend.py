#!/usr/bin/env python3
"""Create a NEW backend copy only. No database, ownership, live writes or services."""
import argparse,hashlib,json,os,shutil,stat
from pathlib import Path
ADMIN={
    '732e68ecf0b499b2e52f8a7269a669f77ba1275b0783e415f80b53b5cc4cfa63',
    '831a44d9b26af670657aafbbc5c82de8532f6f2fef1e40a85dcf1d58e04f45db',
}
ACTIONS='a90f113d06b04b3a13ac42565bff4303f15089c4cc93c1f3a218915da4416c5f'
def sha(b):return hashlib.sha256(b).hexdigest()
def prepare(source,output):
    source=Path(source).resolve();output=Path(output).absolute()
    if os.path.lexists(output) or output==source or source in output.parents:
        raise ValueError('fresh external backend copy required')
    nodes=list(source.rglob('*'))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in nodes):
        raise ValueError('regular backend source required')
    a=source/'app/Security/Admin.php';b=source/'app/Admin/Actions.php'
    ab=a.read_bytes();bb=b.read_bytes()
    if sha(ab) not in ADMIN or sha(bb)!=ACTIONS:raise ValueError('exact reviewed backend input required')
    payload=(Path(__file__).with_name('avatar-storage.inc.php')).read_text(encoding='utf-8')
    prefix='<?php\ndeclare(strict_types=1);\n'
    assert payload.startswith(prefix)
    text=ab.decode();start=text.index('function safe_avatar(');end=text.index('function safe_image_url(',start)
    if 'function avatar_directory' in text:raise ValueError('already changed')
    revised=text[:start]+payload[len(prefix):]+text[end:]
    actions=bb.decode();marker="        } elseif (isset($_POST['update_profile'])) {"
    start=actions.index(marker)+len(marker);end=actions.index('            $msg = ',start)
    revised_actions=actions[:start]+'''
            update_admin_profile(
                $db, $_POST['admin_username'] ?? '', $_POST['avatar_type'] ?? '',
                isset($_FILES['admin_avatar_file']) && is_array($_FILES['admin_avatar_file']) ? $_FILES['admin_avatar_file'] : null,
                $_POST['admin_avatar_url'] ?? ''
            );
'''+actions[end:]
    shutil.copytree(source,output)
    (output/'app/Security/Admin.php').write_text(revised,encoding='utf-8',newline='\n')
    (output/'app/Admin/Actions.php').write_text(revised_actions,encoding='utf-8',newline='\n')
    assert a.read_bytes()==ab and b.read_bytes()==bb
    return {'source_unchanged':True,'output':str(output),'changed':['app/Security/Admin.php','app/Admin/Actions.php'],
        'production_modified':False,'required_preparation':'dedicated external avatar directory and reviewed loopback-admin alias, not installed'}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--source',required=True);a.add_argument('--out',required=True);v=a.parse_args()
    print(json.dumps(prepare(v.source,v.out)))
