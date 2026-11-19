#!/usr/bin/env python3
"""Render reviewed MariaDB grants for a NEW dedicated authority account; never connects to SQL."""
import argparse
import json
from pathlib import Path
import re
import sys

COLUMNS = {
    "cards": "id,app_id,card_code,status,device_hash,expire_time,data_epoch",
    "applications": "id,status,key_version,api_secret",
    "active_devices": "card_code,app_id,device_hash,status,expire_time",
    "api_sessions": "session_id,app_id,card_code,device_hash,key_version,expires_at",
    "blacklists": "id,type,value",
}

def render(config):
    raw=Path(config).read_bytes()
    if len(raw)>4096:raise ValueError("config too large")
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError("duplicate key")
            d[k]=v
        return d
    c=json.loads(raw,object_pairs_hook=pairs)
    if not isinstance(c,dict) or set(c)!={"schema","database","account","host"} or type(c['schema']) is not int or c['schema']!=1 or c['host']!='127.0.0.1':
        raise ValueError("exact schema and loopback account required")
    if not isinstance(c['database'],str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',c['database']):raise ValueError("database identifier")
    if not isinstance(c['account'],str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,25}_data',c['account']):raise ValueError("dedicated *_data account required; never root or Web identity")
    db='`'+c['database']+'`';account="'"+c['account']+"'@'127.0.0.1'"
    lines=["-- ADMIN REVIEW ONLY. New dedicated account, no inherited roles; credentials provisioned separately.",
           "-- REVOKE affects this dedicated identity globally. Never use a shared/Web account.",
           "-- No CREATE USER, password, DDL, FILE, SUPER or GRANT OPTION is granted.",
           'REVOKE ALL PRIVILEGES, GRANT OPTION FROM '+account+';']
    lines += ['GRANT SELECT ('+columns+') ON '+db+'.`'+table+'` TO '+account+';' for table,columns in COLUMNS.items()]
    lines += ['GRANT SELECT,INSERT,UPDATE ON '+db+'.`data_device_keys` TO '+account+';']
    return '\n'.join(lines)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    try:
        sql=render(a.config)
        with Path(a.out).open('x',encoding='utf-8',newline='\n') as f:f.write(sql)
    except (OSError,ValueError,TypeError,UnicodeError):
        print('GRANTS_RENDER_DENIED: invalid non-secret config or output exists; no database connection attempted',file=sys.stderr);return 2
    print('GRANTS_RENDERED_REVIEW_ONLY: dedicated column/table matrix; no SQL executed');return 0
if __name__=='__main__':raise SystemExit(main())
