"""Offline non-secret grants renderer checks. No database/network access."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import render_data_grants as grants

class GrantsTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(os.environ.get('GS_DATA_GRANTS_TEST_DIR',tempfile.gettempdir())).resolve();self.base.mkdir(parents=True,exist_ok=True)
        self.root=self.base/('gs-grants-test-'+uuid.uuid4().hex);self.root.mkdir()
        def cleanup():
            assert self.root.resolve().parent==self.base and self.root.name.startswith('gs-grants-test-')
            shutil.rmtree(self.root)
        self.addCleanup(cleanup)
        self.good={'schema':1,'database':'guyi_dataauth_phase6','account':'gs6_data','host':'127.0.0.1'}
    def config(self,c):
        p=self.root/'input.json';p.write_text(json.dumps(c),encoding='utf-8');return p
    def test_narrow_projection_and_key_registration_only(self):
        sql=grants.render(self.config(self.good))
        self.assertEqual(sql.count('GRANT SELECT'),6)
        self.assertIn('REVOKE ALL PRIVILEGES, GRANT OPTION',sql)
        self.assertIn('SELECT (id,app_id,card_code,status,device_hash,expire_time,data_epoch)',sql)
        statements='\n'.join(x for x in sql.splitlines() if not x.startswith('--'))
        self.assertNotIn('custom_data',statements);self.assertNotIn('duration',statements);self.assertNotIn('IDENTIFIED',statements)
        self.assertNotIn('GRANT ALL',statements);self.assertNotIn('CREATE USER',statements);self.assertNotIn('WITH GRANT OPTION',statements)
        self.assertIn('GRANT SELECT,INSERT,UPDATE ON `guyi_dataauth_phase6`.`data_device_keys`',sql)
    def test_invalid_nonsecret_identifiers_reject(self):
        for k,v in [('database',''),('database','db;DROP DATABASE db'),('database','x\nGRANT ALL'),('account','root'),('account','gs6_web'),('host','%'),('host','localhost'),('schema',True),('password','SYNTHETIC')]:
            c=self.good.copy();c[k]=v
            with self.subTest(field=k),self.assertRaises(ValueError):grants.render(self.config(c))
    def test_duplicate_fields_reject(self):
        p=self.root/'input.json';p.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):grants.render(p)
    def test_existing_output_preserved(self):
        p=self.config(self.good);out=self.root/'existing.sql';out.write_bytes(b'pristine')
        x=subprocess.run([sys.executable,'-B',str(Path(grants.__file__)),'--config',str(p),'--out',str(out)],capture_output=True)
        self.assertEqual(x.returncode,2);self.assertEqual(out.read_bytes(),b'pristine')

if __name__=='__main__':unittest.main(verbosity=2)
