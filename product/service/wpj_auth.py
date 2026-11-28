"""Distinct pre-registration OAuth experiment. Never creates a device.

Live: one explicit native session, one code POST, two public issuer-key GETs.
No scope/claim fallback, broker emulation, refresh, device-code or retry.
"""
from dataclasses import asdict
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import re
import secrets
import subprocess
import time
from urllib.parse import urlencode, parse_qsl, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import ngc_bootstrap as n
import wpj_protocol as w
import wpj_http

CLIENT_ID="29d9ed98-a469-4536-ade2-f981bc1d605e"
REDIRECT="msauth://Microsoft.AAD.BrokerPlugin"
EXPERIMENT="WPJ-A01"
HELPER=Path(__file__).resolve().parents[1]/'build/WorkplaceJoinBootstrap/Device Registration Authorization.app'


def prepare(metadata, designated, *, now=None, verifier=None, state=None):
    now=int(time.time()) if now is None else now
    designated=n.identity(designated)
    w.require(type(metadata) is w.Discovery and designated['tenant_id']==metadata.tenant_id,"designated_identity_mismatch")
    authorize=n.msal_endpoint(metadata.authorize_endpoint,'authorize',metadata.tenant_id)
    n.msal_endpoint(metadata.token_endpoint,'token',metadata.tenant_id)
    verifier=verifier or secrets.token_urlsafe(32);state=state or secrets.token_urlsafe(32)
    w.require(type(now) is int and now>0 and isinstance(state,str) and re.fullmatch(r'[A-Za-z0-9_-]{43}',state),"invalid_authorization_state")
    params={'client_id':CLIENT_ID,'redirect_uri':REDIRECT,'response_type':'code','response_mode':'query',
        'scope':n.msal_scopes(metadata.registration_resource),'login_hint':designated['account'],'hsu':'1',
        'state':state,'code_challenge':n.pkce(verifier),'code_challenge_method':'S256','msafed':'0'}
    # No deviceid claims belong to this initial WPJ authorization operation.
    # B03's later provisioning claims are preserved in their separate module.
    native={'v':1,'experiment':EXPERIMENT,'authorize_url':authorize+'?'+urlencode(params),
        'authorize_endpoint':authorize,'tenant_id':metadata.tenant_id,'callback_scheme':'msauth',
        'callback_host':'Microsoft.AAD.BrokerPlugin','callback_path':'','state':state,'expires_at':now+600}
    private={'v':1,'experiment':EXPERIMENT,'identity':designated,'discovery':asdict(metadata),
        'created_at':now,'expires_at':now+600,'verifier':verifier,'state':state}
    return native,private


def validate_state(value,now=None):
    now=time.time() if now is None else now
    w.require(isinstance(value,dict) and set(value)=={'v','experiment','identity','discovery','created_at','expires_at','verifier','state'} and type(value['v']) is int and value['v']==1 and value['experiment']==EXPERIMENT,"invalid_authorization_state")
    w.require(type(value['created_at']) is int and type(value['expires_at']) is int and value['created_at']<=now+3 and value['expires_at']==value['created_at']+600 and now<value['expires_at'],"authorization_expired")
    try:metadata=w.Discovery(**value['discovery'])
    except (TypeError,KeyError):raise w.WpjError('invalid_authorization_state') from None
    prepare(metadata,value['identity'],now=value['created_at'],verifier=value['verifier'],state=value['state'])
    return metadata


def callback(raw,state,*,now=None):
    validate_state(state,now)
    value=w.parse_json(raw,65536)
    w.require(set(value)=={'v','experiment','callback_url'} and type(value['v']) is int and value['v']==1 and value['experiment']==EXPERIMENT,"invalid_callback")
    url=value['callback_url']
    w.require(isinstance(url,str) and len(url)<=65536 and all(32<=ord(c)<127 for c in url) and '\\' not in url,"invalid_callback")
    try:
        p=urlsplit(url)
        w.require(p.scheme=='msauth' and p.netloc.lower()=='microsoft.aad.brokerplugin' and not p.path and not p.fragment,"callback_destination_mismatch")
        w.require(re.search(r'%(?![0-9a-fA-F]{2})',p.query) is None,'invalid_callback')
        pairs=parse_qsl(p.query,keep_blank_values=True,strict_parsing=True,max_num_fields=16,errors='strict')
    except (ValueError,UnicodeError):raise w.WpjError('invalid_callback') from None
    values=dict(pairs)
    w.require(len(values)==len(pairs) and all(len(k.encode())<=32768 and len(v.encode())<=32768 for k,v in pairs),'invalid_callback')
    w.require(values.get('state')==state['state'],'callback_state_mismatch')
    w.require(('code' in values)!=('error' in values),'invalid_callback')
    if 'error' in values:raise w.WpjError('authorization_rejected')
    code=values['code'];w.require(0<len(code)<=16384 and all(32<=ord(c)<127 for c in code),'invalid_callback')
    return code


def receipt(raw):
    value=w.parse_json(raw)
    w.require(value.get('experiment')==EXPERIMENT,'invalid_native_result')
    # Reuse only the fixed receipt invariants; native execution is a separate app.
    translated=dict(value);translated['experiment']='NGC-B01'
    if translated.get('status')=='device_management_prompt_stopped':translated['status']='cancelled'
    n.native_result(w.encode(translated))
    return value


def code_request(state,raw,*,now=None):
    metadata=validate_state(state,now)
    code=callback(raw,state,now=now)
    return n.msal_endpoint(metadata.token_endpoint,'token',metadata.tenant_id),urlencode({
        'client_id':CLIENT_ID,'grant_type':'authorization_code','redirect_uri':REDIRECT,'code':code,
        'code_verifier':state['verifier'],'scope':n.msal_scopes(metadata.registration_resource)}).encode()


def issuer_metadata(raw,tenant):
    value=w.parse_json(raw)
    expected=('https://sts.windows.net/'+tenant+'/', 'https://login.microsoftonline.com/'+tenant+'/v2.0')
    issuer=value.get('issuer')
    w.require(issuer in expected,'issuer_mismatch')
    jwks=value.get('jwks_uri');wpj_http.validate_destination('jwks','GET',jwks,tenant)
    return issuer,jwks


def unurl(value):
    w.require(isinstance(value,str) and len(value)<=65536 and re.fullmatch(r'[A-Za-z0-9_-]+',value),'invalid_jwt')
    try:raw=base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    except ValueError:raise w.WpjError('invalid_jwt') from None
    w.require(w.b64url(raw)==value,'invalid_jwt')
    return raw


def verified_token(raw,metadata_raw,jwks_raw,designated,resource,*,now=None):
    """Validate signature AND designated tenant/object/audience/lifetime."""
    now=int(time.time()) if now is None else now
    designated=n.identity(designated);issuer,_=issuer_metadata(metadata_raw,designated['tenant_id'])
    value=w.parse_json(raw)
    w.require(isinstance(value.get('token_type'),str) and value['token_type'].lower()=='bearer','token_not_bearer')
    token=value.get('access_token');w.require(isinstance(token,str) and len(token)<=65536,'access_token_missing')
    parts=token.split('.');w.require(len(parts)==3,'opaque_or_encrypted_token_not_supported')
    header=w.parse_json(unurl(parts[0]),8192);claims=w.parse_json(unurl(parts[1]),65536)
    w.require(header.get('alg')=='RS256' and not any(k in header for k in ('crit','jku','jwk','x5u')),'unsupported_jwt_header')
    kid=header.get('kid');w.require(isinstance(kid,str) and 0<len(kid)<=256,'jwt_key_id_missing')
    keys=w.parse_json(jwks_raw).get('keys');w.require(isinstance(keys,list) and 0<len(keys)<=64,'invalid_issuer_keys')
    matching=[key for key in keys if isinstance(key,dict) and key.get('kid')==kid]
    w.require(len(matching)==1,'issuer_key_ambiguous_or_missing');key=matching[0]
    w.require(key.get('kty')=='RSA' and key.get('use','sig')=='sig' and key.get('alg','RS256')=='RS256','unsupported_issuer_key')
    if 'issuer' in key:
        w.require(isinstance(key['issuer'],str) and key['issuer'].replace('{tenantid}',designated['tenant_id'])==issuer,'issuer_key_tenant_mismatch')
    try:
        exponent,modulus=unurl(key['e']),unurl(key['n'])
        w.require(len(exponent)<=8 and 256<=len(modulus)<=1024,'invalid_issuer_key_size')
        pub=rsa.RSAPublicNumbers(int.from_bytes(exponent,'big'),int.from_bytes(modulus,'big')).public_key()
        w.require(pub.key_size>=2048,'weak_issuer_key')
        pub.verify(unurl(parts[2]),(parts[0]+'.'+parts[1]).encode(),padding.PKCS1v15(),hashes.SHA256())
    except (ValueError,KeyError,InvalidSignature):raise w.WpjError('invalid_token_signature') from None
    w.require(claims.get('iss')==issuer and claims.get('tid')==designated['tenant_id'] and claims.get('oid')==designated['object_id'],'token_identity_mismatch')
    client_claims=[claims[name] for name in ('appid','azp') if name in claims]
    w.require(client_claims and all(value==CLIENT_ID for value in client_claims),'token_client_mismatch')
    w.require(resource in n.RESOURCES and claims.get('aud')==resource,'token_audience_mismatch')
    w.require(type(claims.get('exp')) is int and now+30<claims['exp']<=now+86400,'token_expired_or_unbounded')
    w.require(type(claims.get('nbf')) is int and claims['nbf']<=now+30,'token_not_yet_valid')
    w.require(type(claims.get('iat')) is int and now-600<=claims['iat']<=now+30,'token_not_fresh')
    for name in ('upn','preferred_username','unique_name'):
        if name in claims:w.require(isinstance(claims[name],str) and claims[name].casefold()==designated['account'].casefold(),'token_account_mismatch')
    return token


def live(directory,metadata,designated,*,http=wpj_http.once,launcher=None,clock=time.monotonic,sleep=time.sleep):
    directory=n.private_dir(directory,create=True)
    n.write_json(directory/'live-attempt.lock',{'experiment':EXPERIMENT,'maximum_sessions':1,'maximum_token_posts':1,'maximum_issuer_gets':2})
    report={'experiment':EXPERIMENT,'stage':'authorization','sessions_attempted':0,'post_attempts':0,'get_attempts':0,
        'maximum_sessions':1,'maximum_token_posts':1,'maximum_issuer_gets':2,
        'automatic_retries':0,'device_registration_performed':False,'token_signature_and_identity_validated':False,'error':None}
    process=None
    try:
        native,state=prepare(metadata,designated)
        n.write_json(directory/'state.json',state);n.write_json(directory/'auth-input.json',native)
        with (HELPER/'Contents/Info.plist').open('rb') as f:info=plistlib.load(f)
        w.require(info['CFBundleIdentifier']=='org.example.microsoftmfamac.WorkplaceJoinBootstrap','wrong_helper')
        binary=HELPER/'Contents/MacOS/WorkplaceJoinBootstrap'
        check=subprocess.run([str(binary),'--validate-input',str(directory/'auth-input.json')],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
        w.require(check.returncode==0 and len(check.stdout)<=4096,'native_input_invalid')
        report['sessions_attempted']=1
        launch=launcher or (lambda:subprocess.Popen(['/usr/bin/open','-n','-W','-a',str(HELPER),'--args','--input',str(directory/'auth-input.json'),'--output',str(directory/'callback.json')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        process=launch();deadline=clock()+602
        while process.poll() is None and clock()<deadline:sleep(.25)
        w.require(process.poll() is not None,'authorization_expired')
        native_result=receipt(n.private_read(directory/'native-result.json'))
        report['native_status']=native_result['status']
        w.require(native_result['terminal'] and native_result['status']=='callback_saved','native_authorization_not_completed')
        url,body=code_request(state,n.private_read(directory/'callback.json'))
        n.write_json(directory/'exchange-attempt.lock',{'maximum_posts':1})
        report['post_attempts']=1
        status,raw=http('token','POST',url,tenant=metadata.tenant_id,body=body)
        n.private_write(directory/'token-response.bin',raw)
        report.update(token_http_status=status,token_tls_verified=True)
        w.require(status==200,'token_http_rejected')
        issuer_url='https://login.microsoftonline.com/'+metadata.tenant_id+'/.well-known/openid-configuration'
        report['get_attempts']+=1
        status,issuer_raw=http('issuer','GET',issuer_url,tenant=metadata.tenant_id)
        n.private_write(directory/'issuer-metadata.json',issuer_raw);w.require(status==200,'issuer_metadata_http_rejected')
        _,jwks_url=issuer_metadata(issuer_raw,metadata.tenant_id)
        report['get_attempts']+=1
        status,jwks_raw=http('jwks','GET',jwks_url,tenant=metadata.tenant_id)
        n.private_write(directory/'issuer-keys.json',jwks_raw);w.require(status==200,'issuer_keys_http_rejected')
        verified_token(raw,issuer_raw,jwks_raw,designated,metadata.registration_resource)
        report.update(stage='authorization_validated',token_signature_and_identity_validated=True,issuer_tls_verified=True)
    except KeyboardInterrupt:report['error']='cancelled_locally'
    except (w.WpjError,n.BootstrapError) as exc:report['error']=str(exc)
    except Exception:report['error']='local_or_network_failure'
    finally:
        if process is not None and process.poll() is None:
            try:process.terminate()
            except OSError:pass
    n.write_json(directory/'report.json',report)
    return report
