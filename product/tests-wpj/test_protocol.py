"""Synthetic keys/certificates only; never load an account or open a socket."""
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import wpj_protocol as w

TENANT = "11111111-2222-3333-4444-555555555555"
DEVICE = "aaaa1111-bbbb-2222-cccc-333333333333"
SESSION = "12345678-1234-1234-1234-123456789abc"
NOW = 1800000000
ACCOUNT = "research@example.test"


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(key):
    return lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def metadata():
    return {"TenantInfo": {"TenantId":TENANT},
        "DeviceJoinService":{"ServiceVersion":"2.0","JoinEndpoint":"https://enterpriseregistration.windows.net/EnrollmentServer/device/","JoinResourceId":"urn:ms-drs:enterpriseregistration.windows.net"},
        "DeviceRegistrationService":{"RegistrationResourceId":"urn:ms-drs:enterpriseregistration.windows.net"},
        "AuthenticationService":{"OAuth2":{"AuthCodeEndpoint":"https://login.microsoftonline.com/common/oauth2/authorize","TokenEndpoint":"https://login.microsoftonline.com/common/oauth2/token"}},
        "DeviceManagementService":{"DeviceManagementEndpoint":"https://evil.example/NEVER-FOLLOW"}}


def cert(key, issuer, tenant=TENANT, device=DEVICE, expiry=NOW+86400, malformed=False, client_auth=True):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DEVICE)])
    issuername = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"MS-Organization-Access")])
    value = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuername).public_key(key.public_key())
        .serial_number(1).not_valid_before(datetime.fromtimestamp(NOW-60, timezone.utc))
        .not_valid_after(datetime.fromtimestamp(expiry, timezone.utc))
        .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client_auth else ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .add_extension(x509.UnrecognizedExtension(w.DEVICE_OID, b"\x04\x10" + uuid.UUID(device).bytes_le),critical=False))
    if tenant is not None:
        value=value.add_extension(x509.UnrecognizedExtension(w.TENANT_OID, b"bad" if malformed else b"\x04\x10"+uuid.UUID(tenant).bytes_le),critical=False)
    value=value.sign(issuer, hashes.SHA256())
    return value.public_bytes(serialization.Encoding.DER)


def challenge():
    return {"Nonce":"synthetic-nonce", "Context":"synthetic-context", "Version":"1.0",
        "SubmitUrl":"https://login.microsoftonline.com/common/DeviceAuthPKeyAuth",
        "CertAuthorities":"CN=MS-Organization-Access", "TenantId":TENANT}


class Protocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.transport = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.issuer = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.spki = spki(cls.key)
        cls.rawcert = cert(cls.key, cls.issuer)

    def challenge(self, value=None, **kwargs):
        return w.challenge(value or challenge(), origin="https://login.microsoftonline.com/common/login", tenant_id=TENANT, browser_session=SESSION, now=NOW, **kwargs)

    def device(self):
        return w.certificate_identity(self.rawcert,self.spki,TENANT,now=NOW)

    def test_csr_proves_key_possession_and_has_exact_attributes(self):
        raw=w.make_csr(self.spki,sign(self.key)); csr=x509.load_der_x509_csr(raw)
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(csr.subject.rfc4514_string(),"CN=AGREEYA")
        self.assertEqual({a.oid.dotted_string for a in csr.attributes},{"2.5.29.15","2.5.29.37"})
        self.assertEqual(csr.signature_hash_algorithm.name,"sha256")

    def test_wrong_signer_rejected_before_request(self):
        with self.assertRaises(w.WpjError): w.make_csr(self.spki,sign(self.transport))

    def test_transport_is_base64_json_not_cng_or_private_material(self):
        encoded=w.encoded_transport_key(spki(self.transport),SESSION)
        data=json.loads(base64.b64decode(encoded))
        self.assertEqual(set(data),{"kty","n","e","alg","kid"})
        self.assertEqual(base64.b64decode(data['e']),b'\x01\x00\x01')
        self.assertEqual(len(base64.b64decode(data['n'])),256)
        self.assertEqual(int.from_bytes(base64.b64decode(data['n']),'big'),self.transport.public_key().public_numbers().n)

    def test_request_only_registers_new_truthful_mac_identity(self):
        raw=w.make_csr(self.spki,sign(self.key))
        discovery=w.discovery(w.encode(metadata()),TENANT)
        url, body=w.registration_request(discovery,raw,self.spki,spki(self.transport),SESSION,"26.1","Mac MFA WPJ research W01")
        data=json.loads(body)
        self.assertEqual(url,"https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0")
        self.assertEqual(set(data),{"CertificateRequest","TransportKey","TargetDomain","DeviceType","OSVersion","DeviceDisplayName","JoinType","Attributes"})
        self.assertEqual((data['DeviceType'],data['JoinType'],data['Attributes']),("MacOS",4,{}))
        self.assertNotIn(b"NEVER-FOLLOW",body)
        self.assertEqual(base64.b64decode(data['CertificateRequest']['Data']),raw)

    def test_host_version_tenant_and_resource_fail_closed(self):
        cases=[('endpoint','https://evil.example/EnrollmentServer/device'),('endpoint','https://enterpriseregistration.windows.net.evil.example/EnrollmentServer/device'),('version','3.0'),('resource','https://graph.microsoft.com')]
        for kind,value in cases:
            with self.subTest(kind=kind,value=value):
                data=metadata()
                if kind=='endpoint':data['DeviceJoinService']['JoinEndpoint']=value
                if kind=='version':data['DeviceJoinService']['ServiceVersion']=value
                if kind=='resource':data['DeviceRegistrationService']['RegistrationResourceId']=value
                with self.assertRaises(w.WpjError):w.discovery(w.encode(data),TENANT)
        with self.assertRaises(w.WpjError):w.discovery(w.encode(metadata()),DEVICE)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(w.WpjError):w.parse_json(b'{"Certificate":{},"Certificate":{}}')

    def test_mixed_endian_certificate_identifiers_and_response(self):
        result=w.registration_response(w.encode({'Certificate':{'RawBody':w.b64(self.rawcert)},'User':{'Upn':ACCOUNT}}),self.spki,TENANT,ACCOUNT,now=NOW)
        self.assertEqual((result.device_id,result.tenant_id),(DEVICE,TENANT))
        self.assertNotIn(DEVICE,repr(result))
        # A matching issuer name is still not an assertion of Microsoft issuance.
        self.assertFalse(hasattr(result,'issuer_authenticated'))

    def test_wrong_key_account_tenant_expiry_and_eku_rejected(self):
        for raw,key,tenant in [(self.rawcert,spki(self.transport),TENANT),(self.rawcert,self.spki,DEVICE),(cert(self.key,self.issuer,expiry=NOW-1),self.spki,TENANT),(cert(self.key,self.issuer,malformed=True),self.spki,TENANT),(cert(self.key,self.issuer,client_auth=False),self.spki,TENANT)]:
            with self.assertRaises(w.WpjError):w.certificate_identity(raw,key,tenant,now=NOW)
        with self.assertRaises(w.WpjError):w.registration_response(w.encode({'Certificate':{'RawBody':w.b64(self.rawcert)},'User':{'Upn':'other@example.test'}}),self.spki,TENANT,ACCOUNT,now=NOW)

    def test_missing_certificate_tenant_is_not_promoted_to_a_certificate_claim(self):
        result=w.certificate_identity(cert(self.key,self.issuer,tenant=None),self.spki,TENANT,now=NOW)
        self.assertIsNone(result.certificate_tenant_id)
        self.assertEqual(result.tenant_id,TENANT)  # Expected operation context only.

    def test_wrapped_raw_body_accepts_only_base64_whitespace(self):
        encoded=w.b64(self.rawcert)
        result=w.registration_response(w.encode({'Certificate':{'RawBody':'\r\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64))+'\n'}}),self.spki,TENANT,ACCOUNT,now=NOW)
        self.assertEqual(result.device_id,DEVICE)
        with self.assertRaises(w.WpjError):w.registration_response(w.encode({'Certificate':{'RawBody':encoded+'!'}}),self.spki,TENANT,ACCOUNT,now=NOW)

    def test_pkeyauth_is_verifiable_and_bound_to_nonce_audience(self):
        header=w.pkeyauth_response(self.challenge(),self.device(),sign(self.key),now=NOW)
        token=header.split('AuthToken="',1)[1].split('"',1)[0]
        head,payload,sig=token.split('.')
        decode=lambda v:base64.urlsafe_b64decode(v+'='*(-len(v)%4))
        self.key.public_key().verify(decode(sig),(head+'.'+payload).encode(),padding.PKCS1v15(),hashes.SHA256())
        self.assertEqual(json.loads(decode(head)),{'alg':'RS256','typ':'JWT','x5c':[w.b64(self.rawcert)]})
        self.assertEqual(json.loads(decode(payload)),{'aud':challenge()['SubmitUrl'],'iat':NOW,'nonce':'synthetic-nonce'})
        self.assertNotIn('compliant',header)

    def test_proof_rejects_untrusted_origin_header_injection_and_stale_request(self):
        for key,value in [('SubmitUrl','https://evil.example/common/DeviceAuthPKeyAuth'),('SubmitUrl','https://login.windows.net/common/DeviceAuthPKeyAuth'),('SubmitUrl','https://login.microsoftonline.com/common/arbitrary'),('Context','bad"\r\nHeader: x'),('Nonce',''),('TenantId',DEVICE),('Version','2.0')]:
            values=challenge(); values[key]=value
            with self.subTest(key=key),self.assertRaises(w.WpjError):self.challenge(values)
        values=challenge();values['nonce']='duplicate'
        with self.assertRaises(w.WpjError):self.challenge(values)
        with self.assertRaises(w.WpjError):w.pkeyauth_response(self.challenge(),self.device(),sign(self.key),now=NOW+120)

    def test_certificate_selector_and_signature_checked(self):
        values=challenge();values['CertAuthorities']='CN=other'
        with self.assertRaises(w.WpjError):w.pkeyauth_response(self.challenge(values),self.device(),sign(self.key),now=NOW)
        values['CertThumbprint']=x509.load_der_x509_certificate(self.rawcert).fingerprint(hashes.SHA1()).hex()
        self.assertTrue(w.pkeyauth_response(self.challenge(values),self.device(),sign(self.key),now=NOW).startswith('PKeyAuth '))
        with self.assertRaises(w.WpjError):w.pkeyauth_response(self.challenge(),self.device(),sign(self.transport),now=NOW)

    def test_durable_proof_budget_never_retries_after_consumption(self):
        consumed=[]
        guard=w.ProofBudget(consumed.append);guard.claim(self.challenge())
        with self.assertRaises(w.WpjError):guard.claim(self.challenge())
        self.assertEqual(len(consumed),1)


if __name__ == '__main__':unittest.main()
