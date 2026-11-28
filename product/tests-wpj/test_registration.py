"""Offline executor tests. All certificates, tokens and key stores are synthetic."""
from pathlib import Path
import os
import json
import ssl
import tempfile
import unittest
from unittest.mock import patch

from test_protocol import metadata,spki,cert,TENANT,ACCOUNT,NOW,DEVICE
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
import wpj_protocol as w
import wpj_registration as r
import wpj_store as s
import wpj_http as h

IDENTITY={'account':ACCOUNT,'tenant_id':TENANT,'object_id':DEVICE}


class FakeKeys:
    pairs={}
    def __init__(self,namespace):self.namespace=namespace
    def create(self,role):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.pairs[(self.namespace,role)]=key;return spki(key)
    def public(self,role):return spki(self.pairs[(self.namespace,role)])
    def sign(self,data):return self.pairs[(self.namespace,'device')].sign(data,padding.PKCS1v15(),hashes.SHA256())


class Registration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path.cwd()/'work')
        self.root=Path(self.temp.name);os.chmod(self.root,0o700)
        self.source=self.root/'source';self.source.mkdir(mode=0o700)
        self.path=self.root/'w01'
        self.raw=w.encode(metadata())
        with patch.object(r.n,'load_validated_cache',return_value=(IDENTITY,None,self.raw)):
            self.review=r.prepare(self.path,self.source,keys_factory=FakeKeys,os_version='26.1')
        self.plan=s.read_json(self.path/'plan.json')
        self.posts=[]

    def tearDown(self):self.temp.cleanup()

    def transport(self,*args,**kwargs):
        self.posts.append((args,kwargs))
        key=FakeKeys.pairs[(self.plan['namespace'],'device')]
        issuer=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        # Certificate fixture time matches the executor's current wall clock.
        raw=cert(key,issuer,expiry=NOW+86400)
        return 200,w.encode({'Certificate':{'RawBody':w.b64(raw)},'User':{'Upn':ACCOUNT}})

    def test_offline_preparation_contains_only_public_keys_and_registration_data(self):
        self.assertFalse(self.posts)
        self.assertEqual(self.review['limits'],{'registration_posts':1,'automatic_retries':0,'mdm_operations':0,'ngc_key_operations':0})
        self.assertFalse(self.review['management_enrollment'])
        self.assertNotIn(ACCOUNT,json.dumps(self.review))
        self.assertEqual(s.read_json(self.path/'request.json')['Attributes'],{})
        for p in self.path.iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertFalse((self.path/'authorization').exists())

    def test_existing_directory_never_reset(self):
        with patch.object(r.n,'load_validated_cache',return_value=(IDENTITY,None,self.raw)):
            with self.assertRaises(w.WpjError):r.prepare(self.path,self.source,keys_factory=FakeKeys,os_version='26.1')

    def test_wrong_approval_or_missing_verified_token_never_posts(self):
        with self.assertRaises(w.WpjError):r.register(self.path,'0'*64,http=self.transport,keys_factory=FakeKeys)
        with self.assertRaises(FileNotFoundError):r.register(self.path,self.review['approval_digest'],http=self.transport,keys_factory=FakeKeys)
        self.assertEqual(self.posts,[])
        self.assertFalse((self.path/'registration-attempt.lock').exists())

    def test_continuous_flow_stops_before_creation_when_auth_fails(self):
        with patch.object(r,'authorize',return_value={'error':'native_authorization_not_completed'}),patch.object(r,'register') as send:
            report=r.execute(self.path,self.review['approval_digest'])
        send.assert_not_called()
        self.assertEqual(report['registration_posts_attempted'],0)

    def test_cleanup_after_uncertain_post_requires_server_revocation_confirmation(self):
        s.write_json(self.path/'registration-attempt.lock',{'attempted':True})
        with patch.object(s,'NativeKeys') as keys:
            with self.assertRaises(w.WpjError):r.cleanup_local(self.path)
        keys.assert_not_called()

    def test_changed_request_cannot_use_old_approval(self):
        with (self.path/'request.json').open('wb') as f:f.write(w.encode({'JoinType':0,'managed':True}))
        with self.assertRaises(w.WpjError):r.register(self.path,self.review['approval_digest'],http=self.transport,keys_factory=FakeKeys)
        self.assertEqual(self.posts,[])

    def test_one_successful_post_binds_certificate_and_consumes_lock(self):
        with patch.object(r,'token',return_value='synthetic-bearer'),patch.object(w.time,'time',return_value=NOW):
            report=r.register(self.path,self.review['approval_digest'],http=self.transport,keys_factory=FakeKeys)
            self.assertIsNone(report['error'])
            self.assertTrue(report['certificate_key_binding_verified'])
            self.assertFalse(report['directory_management_state_verified'])
            self.assertFalse(report['device_proof_server_accepted'])
            with self.assertRaises(FileExistsError):r.register(self.path,self.review['approval_digest'],http=self.transport,keys_factory=FakeKeys)
        self.assertEqual(len(self.posts),1)
        issued=s.read_json(self.path/'issued-identity.json')
        self.assertEqual(issued['device_id'],DEVICE)
        self.assertNotEqual(issued['device_id'],self.plan['namespace'])

    def test_uncertain_send_never_retries_or_cleans_keys(self):
        def failure(*args,**kwargs):self.posts.append(args);raise TimeoutError()
        with patch.object(r,'token',return_value='synthetic-bearer'):
            report=r.register(self.path,self.review['approval_digest'],http=failure,keys_factory=FakeKeys)
            self.assertEqual(report['error'],'local_or_network_failure_do_not_retry')
            self.assertEqual(report['server_side_effect'],'unknown_until_response')
            with self.assertRaises(FileExistsError):r.register(self.path,self.review['approval_digest'],http=failure,keys_factory=FakeKeys)
        self.assertEqual(len(self.posts),1)
        self.assertIn((self.plan['namespace'],'device'),FakeKeys.pairs)

    def test_non_success_response_is_retained_but_never_followed(self):
        def redirect(*args,**kwargs):self.posts.append(args);return 302,b'{"Location":"https://management.example/profile"}'
        with patch.object(r,'token',return_value='synthetic-bearer'):
            report=r.register(self.path,self.review['approval_digest'],http=redirect,keys_factory=FakeKeys)
        self.assertEqual(report['error'],'registration_http_rejected')
        self.assertEqual(len(self.posts),1)
        self.assertFalse((self.path/'issued-identity.json').exists())


class StorageAndTransport(unittest.TestCase):
    def test_symlinks_and_public_permissions_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()/'work') as temp:
            root=Path(temp);os.chmod(root,0o700)
            p=root/'private';p.mkdir(mode=0o700)
            s.write(p/'one',b'private synthetic')
            (p/'link').symlink_to(p/'one')
            with self.assertRaises(OSError):s.read(p/'link')
            os.chmod(p/'one',0o644)
            with self.assertRaises(w.WpjError):s.read(p/'one')
            alias=root/'alias';alias.symlink_to(p,target_is_directory=True)
            with self.assertRaises(w.WpjError):s.directory(alias)

    def test_http_tls_and_purpose_allowlist_without_network(self):
        seen=[]
        class Response:
            status=302
            def read1(self,*args):return b''
        class Connection:
            sock=None
            def __init__(self,host,port,**kwargs):
                seen.append((host,port,kwargs['context'].check_hostname,kwargs['context'].verify_mode))
            def request(self,*args,**kwargs):seen.append((args,kwargs))
            def getresponse(self):return Response()
            def close(self):pass
        url='https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0'
        self.assertEqual(h.once('registration','POST',url,tenant=TENANT,body=b'{}',bearer='synthetic',request_id=DEVICE,connection_factory=Connection),(302,b''))
        self.assertEqual(seen[0],('enterpriseregistration.windows.net',443,True,ssl.CERT_REQUIRED))
        self.assertEqual(len(seen),2)
        for bad in ('https://evil.example/EnrollmentServer/device/?api-version=2.0','http://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0','https://enterpriseregistration.windows.net/EnrollmentServer/management/?api-version=2.0'):
            with self.assertRaises(w.WpjError):h.once('registration','POST',bad,tenant=TENANT,body=b'{}',bearer='synthetic',request_id=DEVICE,connection_factory=Connection)
        self.assertEqual(len(seen),2)

    def test_native_adapter_passes_signing_material_only_through_stdin(self):
        class Completed:
            returncode=0
            stdout=w.encode({'v':1,'ok':True,'action':'sign','namespace':DEVICE,'role':'device','algorithm':'RS256','signature_base64':w.b64(b'x'*256)})
        with patch.object(s.subprocess,'run',return_value=Completed()) as invoke:
            self.assertEqual(s.NativeKeys(DEVICE).sign(b'synthetic-private-challenge'),b'x'*256)
            args,kwargs=invoke.call_args
            self.assertEqual(len(args[0]),1)
            self.assertNotIn('synthetic-private-challenge',str(args))
            self.assertIn(w.b64(b'synthetic-private-challenge').encode(),kwargs['input'])


if __name__=='__main__':unittest.main()
