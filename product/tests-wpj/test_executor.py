"""Full authorization orchestration with synthetic services, no UI or network."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import test_auth as fixtures
from test_auth import discovery,IDENTITY,receipt
import wpj_auth as a
import wpj_protocol as w
import wpj_store as s
import wpj_registration as r


class Executor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.TokenVerification.setUpClass()

    def fixture(self,now):
        fixture=fixtures.TokenVerification()
        claims=fixture.claims(iat=now,nbf=now-1,exp=now+3600)
        return w.encode({'token_type':'Bearer','access_token':fixture.token(claims=claims)}),w.encode(fixture.metadata()),w.encode({'keys':[fixture.key()]})

    def run_case(self,root,status='callback_saved',token_status=200):
        path=root/'authorization';calls=[]
        def launch():
            state=s.read_json(path/'state.json')
            s.write_json(path/'native-result.json',receipt(status))
            if status=='callback_saved':
                from urllib.parse import urlencode
                s.write_json(path/'callback.json',{'v':1,'experiment':'WPJ-A01','callback_url':a.REDIRECT+'?'+urlencode({'code':'SYNTHETIC_CODE','state':state['state']})})
            class Process:
                def poll(self):return 0
            return Process()
        def http(purpose,method,url,**kwargs):
            calls.append(purpose)
            token,metadata,jwks=self.fixture(int(time.time()))
            return (token_status,token) if purpose=='token' else (200,metadata if purpose=='issuer' else jwks)
        class Validated:returncode=0;stdout=b'{}'
        with patch.object(a.subprocess,'run',return_value=Validated()):
            report=a.live(path,discovery(),IDENTITY,http=http,launcher=launch)
        return path,report,calls

    def test_entire_authorization_has_one_post_two_gets_and_no_registration(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()/'work') as tmp:
            root=Path(tmp);os.chmod(root,0o700)
            path,report,calls=self.run_case(root)
            self.assertIsNone(report['error'])
            self.assertEqual(calls,['token','issuer','jwks'])
            self.assertTrue(report['token_signature_and_identity_validated'])
            self.assertFalse(report['device_registration_performed'])
            self.assertTrue((path/'exchange-attempt.lock').exists())
            with self.assertRaises(FileExistsError):a.live(path,discovery(),IDENTITY,http=lambda *a,**k:self.fail('retry'))

    def test_management_stop_has_no_token_requests(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()/'work') as tmp:
            path,report,calls=self.run_case(Path(tmp),'device_management_prompt_stopped')
            self.assertEqual(report['native_status'],'device_management_prompt_stopped')
            self.assertEqual(calls,[])
            self.assertFalse((path/'exchange-attempt.lock').exists())

    def test_token_rejection_does_not_fetch_keys_or_retry(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()/'work') as tmp:
            path,report,calls=self.run_case(Path(tmp),token_status=400)
            self.assertEqual(report['error'],'token_http_rejected')
            self.assertEqual(calls,['token'])
            self.assertTrue((path/'exchange-attempt.lock').exists())


if __name__=='__main__':unittest.main()
