"""W01 registration-only experiment. Prepare/review offline; creation gated.

Authorization is a separate WPJ-A01 session. register requires explicit approval
of the exact prepared request digest, a fresh verified registration token, and
its own durable one-POST lock. No profile/agent/MDM/NGC-key endpoint exists here.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import uuid
import time

import ngc_bootstrap as n
import wpj_protocol as w
import wpj_auth as auth
import wpj_http
import wpj_store as store


def load(directory):
    directory=store.directory(directory)
    plan=store.read_json(directory/'plan.json')
    w.require(set(plan)=={'v','experiment','namespace','display_name','os_version','identity','metadata_sha256','body_sha256','device_spki_sha256','transport_spki_sha256','transport_id','endpoint','limits'} and type(plan['v']) is int and plan['v']==1 and plan['experiment']=='WPJ-W01','invalid_registration_plan')
    w.canonical_uuid(plan['namespace']);w.canonical_uuid(plan['transport_id'])
    w.require(plan['limits']=={'registration_posts':1,'automatic_retries':0,'mdm_operations':0,'ngc_key_operations':0},'invalid_registration_limits')
    metadata_raw=store.read(directory/'discovery-response.bin')
    w.require(hashlib.sha256(metadata_raw).hexdigest()==plan['metadata_sha256'],'discovery_changed')
    designated=n.identity(plan['identity']);metadata=w.discovery(metadata_raw,designated['tenant_id'])
    body=store.read(directory/'request.json')
    device=store.read(directory/'device-public.der');transport=store.read(directory/'transport-public.der')
    w.require(hashlib.sha256(device).hexdigest()==plan['device_spki_sha256'] and hashlib.sha256(transport).hexdigest()==plan['transport_spki_sha256'],'prepared_public_key_changed')
    endpoint,expected=w.registration_request(metadata,store.read(directory/'request.csr.der'),device,transport,plan['transport_id'],plan['os_version'],plan['display_name'])
    w.require(body==expected and hashlib.sha256(body).hexdigest()==plan['body_sha256'] and endpoint==plan['endpoint'],'prepared_request_changed')
    return directory,plan,metadata,body


def digest(plan):return hashlib.sha256(w.encode(plan)).hexdigest()


def review(directory):
    _,plan,metadata,body=load(directory)
    return {'experiment':'WPJ-W01','stage':'prepared_for_review','device_name':plan['display_name'],
        'device_type':'MacOS','os_version':plan['os_version'],'join_type':4,'attributes':{},
        'registration_endpoint':plan['endpoint'],'request_bytes':len(body),'approval_digest':digest(plan),
        'public_keys':{'device':'RSA 2048','transport':'RSA 2048','storage':'separate nonexportable login-Keychain keys'},
        'csr_subject':'CN=AGREEYA (traced SDK placeholder)','account_and_tenant':'privately designated existing account',
        'disclosed_fields':['CertificateRequest.Type','CertificateRequest.Data','TransportKey','TargetDomain','DeviceType','OSVersion','DeviceDisplayName','JoinType','Attributes'],
        'transport_metadata':['source IP and ordinary HTTPS metadata','research client name/version','fresh request correlation ID'],
        'expected_effect':'one new Entra registered device identity and issuer certificate if accepted',
        'management_enrollment':False,'compliance_assertion':False,'attestation_assertion':False,
        'native_mac_acceptance_established':False,'remote_ngc_provisioning_established':False,
        'limits':plan['limits'],'approval_required_before_registration':True,'network_requests':0}


def prepare(directory,source,*,keys_factory=store.NativeKeys,os_version=None):
    # Read only validated issuer metadata and designated identity; never copy
    # consumed state, codes, callbacks, tokens or existing credential material.
    source=store.directory(source)
    designated,_,raw=n.load_validated_cache(source)
    metadata=w.discovery(raw,designated['tenant_id'])
    version=os_version or platform.mac_ver()[0]
    w.require(platform.system()=='Darwin' or os_version is not None,'macos_required')
    path=Path(directory)
    w.require(not os.path.lexists(path),'fresh_registration_directory_required')
    path=store.directory(path,create=True)
    namespace=str(uuid.uuid4());transport_id=str(uuid.uuid4())
    store.write_json(path/'preparation.lock',{'experiment':'WPJ-W01','namespace':namespace,'network_requests':0})
    keys=keys_factory(namespace)
    device=keys.create('device');store.write(path/'device-public.der',device)
    transport=keys.create('transport');store.write(path/'transport-public.der',transport)
    csr=w.make_csr(device,keys.sign);store.write(path/'request.csr.der',csr)
    name='Mac MFA WPJ research W01'
    endpoint,body=w.registration_request(metadata,csr,device,transport,transport_id,version,name)
    store.write(path/'discovery-response.bin',raw);store.write(path/'request.json',body)
    plan={'v':1,'experiment':'WPJ-W01','namespace':namespace,'display_name':name,'os_version':version,
        'identity':designated,'metadata_sha256':hashlib.sha256(raw).hexdigest(),'body_sha256':hashlib.sha256(body).hexdigest(),
        'device_spki_sha256':hashlib.sha256(device).hexdigest(),'transport_spki_sha256':hashlib.sha256(transport).hexdigest(),
        'transport_id':transport_id,'endpoint':endpoint,'limits':{'registration_posts':1,'automatic_retries':0,'mdm_operations':0,'ngc_key_operations':0}}
    store.write_json(path/'plan.json',plan)
    store.write_json(path/'review.json',review(path))
    return review(path)


def authorize(directory):
    path,plan,metadata,_=load(directory)
    authdir=path/'authorization'
    w.require(not os.path.lexists(authdir),'authorization_already_attempted')
    return auth.live(authdir,metadata,plan['identity'])


def token(directory,plan,metadata):
    authdir=directory/'authorization'
    report=store.read_json(authdir/'report.json')
    w.require(report.get('experiment')==auth.EXPERIMENT and report.get('error') is None and report.get('stage')=='authorization_validated' and report.get('token_signature_and_identity_validated') is True and report.get('token_tls_verified') is True and report.get('issuer_tls_verified') is True and report.get('post_attempts')==1 and report.get('get_attempts')==2,'verified_authorization_required')
    native=auth.receipt(store.read(authdir/'native-result.json'))
    w.require(native['terminal'] and native['status']=='callback_saved','verified_authorization_required')
    return auth.verified_token(store.read(authdir/'token-response.bin'),store.read(authdir/'issuer-metadata.json'),store.read(authdir/'issuer-keys.json'),plan['identity'],metadata.registration_resource)


def register(directory,approved_digest,*,http=wpj_http.once,keys_factory=store.NativeKeys):
    path,plan,metadata,body=load(directory)
    w.require(isinstance(approved_digest,str) and hmac.compare_digest(approved_digest,digest(plan)),'approval_for_exact_plan_required')
    keys=keys_factory(plan['namespace'])
    w.require(keys.public('device')==store.read(path/'device-public.der') and keys.public('transport')==store.read(path/'transport-public.der'),'keychain_binding_mismatch')
    bearer=token(path,plan,metadata)
    store.write_json(path/'registration-attempt.lock',{'experiment':'WPJ-W01','approved_digest':approved_digest,'maximum_posts':1,'started_utc_seconds':int(time.time())})
    report={'experiment':'WPJ-W01','stage':'registration','registration_posts_attempted':1,'automatic_retries':0,
        'mdm_operations':0,'ngc_key_operations':0,'tls_verified':False,'certificate_key_binding_verified':False,
        'microsoft_issuance_via_authenticated_tls':False,'certificate_chain_independently_validated':False,
        'directory_management_state_verified':False,'device_proof_server_accepted':False,'error':None,
        'server_side_effect':'unknown_until_response','cleanup_required_if_abandoning':True}
    try:
        status,raw=http('registration','POST',plan['endpoint'],tenant=metadata.tenant_id,body=body,bearer=bearer,request_id=str(uuid.uuid4()))
        store.write(path/'registration-response.bin',raw)
        report.update(http_status=status,tls_verified=True,received_bytes=len(raw))
        w.require(status in (200,201),'registration_http_rejected')
        device=w.registration_response(raw,store.read(path/'device-public.der'),metadata.tenant_id,plan['identity']['account'])
        store.write(path/'device-certificate.der',device.certificate_der)
        # Actual device ID comes only from the issued certificate, never local UUID.
        store.write_json(path/'issued-identity.json',{'v':1,'experiment':'WPJ-W01','device_id':device.device_id,
            'tenant_id':device.tenant_id,'certificate_tenant_extension':device.certificate_tenant_id,
            'certificate_sha256':device.fingerprint,'namespace':plan['namespace'],'expires_at':device.expires_at,
            'request_sha256':plan['body_sha256'],'response_sha256':hashlib.sha256(raw).hexdigest(),
            'issuer_evidence':'exact_allowlisted_registration_endpoint_verified_tls'})
        report.update(stage='certificate_received',certificate_key_binding_verified=True,
            microsoft_issuance_via_authenticated_tls=True,server_side_effect='new_device_registration_accepted',
            certificate_tenant_extension_present=device.certificate_tenant_id is not None)
    except (w.WpjError,n.BootstrapError) as exc:report['error']=str(exc)
    except KeyboardInterrupt:report['error']='cancelled_after_claim_do_not_retry'
    except Exception:report['error']='local_or_network_failure_do_not_retry'
    store.write_json(path/'registration-report.json',report)
    return report


def execute(directory,approved_digest):
    """One approved session through registration, never continuing past W01."""
    _,plan,_,_=load(directory)
    w.require(isinstance(approved_digest,str) and hmac.compare_digest(approved_digest,digest(plan)),'approval_for_exact_plan_required')
    authorization=authorize(directory)
    if authorization.get('error'):
        return {'experiment':'WPJ-W01','stage':'stopped_before_registration','authorization':authorization,
            'registration_posts_attempted':0,'error':'authorization_not_completed'}
    registration=register(directory,approved_digest)
    return {'experiment':'WPJ-W01','authorization':authorization,'registration':registration,
        'error':registration.get('error'),'mdm_operations':0,'ngc_key_operations':0}


def cleanup_local(directory,server_revoked=False):
    """Remove only these two research keys. Never represent this as revocation."""
    path=store.directory(directory)
    preparation=store.read_json(path/'preparation.lock')
    w.require(preparation.get('experiment')=='WPJ-W01','invalid_preparation_lock')
    namespace=w.canonical_uuid(preparation.get('namespace'))
    w.require(not (path/'registration-attempt.lock').exists() or server_revoked,'server_revocation_confirmation_required')
    keys=store.NativeKeys(namespace)
    removed={role:keys.call('delete',role).get('deleted') is True for role in ('device','transport')}
    # Preserve locks/evidence. Neither tenant deletion nor token invalidation is
    # performed here; those are distinct remote cleanup actions.
    return {'experiment':'WPJ-W01','stage':'local_keys_removed','keys_removed':removed,
        'remote_revocation_performed':False,'audit_files_preserved':True,'network_requests':0}


def main():
    parser=argparse.ArgumentParser(description='Registration-only research; never enrolls management or NGC keys.')
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('prepare','review','authorize','register','execute','cleanup-local'):
        p=sub.add_parser(name);p.add_argument('--directory',required=True)
        if name=='prepare':p.add_argument('--from-cache',required=True)
        if name in ('authorize','execute'):p.add_argument('--one-session',required=True,action='store_true')
        if name in ('register','execute'):p.add_argument('--approved-plan',required=True)
        if name=='register':p.add_argument('--one-request',required=True,action='store_true')
        if name=='cleanup-local':p.add_argument('--server-revocation-confirmed',action='store_true')
    args=parser.parse_args()
    try:
        if args.command=='prepare':result=prepare(args.directory,args.from_cache)
        elif args.command=='review':result=review(args.directory)
        elif args.command=='authorize':result=authorize(args.directory)
        elif args.command=='execute':result=execute(args.directory,args.approved_plan)
        elif args.command=='cleanup-local':result=cleanup_local(args.directory,args.server_revocation_confirmed)
        else:result=register(args.directory,args.approved_plan)
    except (w.WpjError,n.BootstrapError) as exc:result={'experiment':'WPJ-W01','error':str(exc)}
    except FileExistsError:result={'experiment':'WPJ-W01','error':'attempt_or_output_already_exists'}
    except Exception:result={'experiment':'WPJ-W01','error':'local_prerequisite_failure'}
    print(json.dumps(result,indent=2,sort_keys=True))
    return 1 if result.get('error') else 0


if __name__=='__main__':raise SystemExit(main())
