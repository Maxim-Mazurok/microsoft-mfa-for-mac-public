"""One-request HTTPS transport. Exact purpose allowlists, no redirects/retry."""
import http.client
import re
import ssl
import time
from urllib.parse import urlsplit
import wpj_protocol as w


def validate_destination(purpose, method, url, tenant):
    w.canonical_uuid(tenant)
    w.require(isinstance(url, str) and len(url) <= 8192 and all(32 < ord(c) < 127 for c in url) and "\\" not in url, "invalid_destination")
    try: p = urlsplit(url)
    except ValueError: raise w.WpjError("invalid_destination") from None
    w.require(p.scheme == "https" and p.netloc == p.hostname and not p.fragment, "invalid_destination")
    if purpose == "registration":
        w.require(method == "POST" and p.hostname == w.DRS and p.path in ("/EnrollmentServer/device", "/EnrollmentServer/device/") and p.query == "api-version=2.0", "invalid_registration_destination")
    elif purpose == "token":
        w.require(method == "POST" and p.hostname in w.bootstrap.AUTH_HOSTS and p.path in tuple('/'+t+'/oauth2/v2.0/token' for t in (tenant,'common','organizations')) and not p.query, "invalid_token_destination")
    elif purpose == "issuer":
        w.require(method == "GET" and p.hostname == "login.microsoftonline.com" and p.path == '/'+tenant+'/.well-known/openid-configuration' and not p.query, "invalid_issuer_destination")
    elif purpose == "jwks":
        w.require(method == "GET" and p.hostname == "login.microsoftonline.com" and p.path in tuple('/'+t+'/discovery/'+v+'keys' for t in (tenant,'common') for v in ('','v2.0/')) and not p.query, "invalid_jwks_destination")
    else: raise w.WpjError("unsupported_request_purpose")
    return p


def once(purpose, method, url, *, tenant, body=None, bearer=None, request_id=None, connection_factory=http.client.HTTPSConnection):
    p = validate_destination(purpose, method, url, tenant)
    w.require(body is None or (isinstance(body, bytes) and len(body) <= w.MAX_BYTES), "invalid_request_body")
    w.require((purpose == "registration") == (bearer is not None), "unexpected_bearer")
    headers = {"Accept":"application/json","User-Agent":"MicrosoftMFAForMac-RegistrationResearch/1"}
    if purpose == "registration":
        w.require(isinstance(bearer,str) and len(bearer) <= 65536 and all(32 < ord(c) < 127 for c in bearer), "invalid_bearer")
        headers.update({"Content-Type":"application/json","Authorization":"Bearer "+bearer,
            "ocp-adrs-client-name":"Microsoft MFA for Mac research","ocp-adrs-client-version":"1.0.0",
            "client-request-id":w.canonical_uuid(request_id)})
    elif purpose == "token": headers['Content-Type']='application/x-www-form-urlencoded'
    connection = connection_factory(p.hostname,443,timeout=30,context=ssl.create_default_context())
    deadline = time.monotonic()+30
    try:
        connection.request(method,p.path+('?' + p.query if p.query else ''),body=body,headers=headers)
        response=connection.getresponse(); blocks=[]; size=0
        while True:
            remaining=deadline-time.monotonic(); w.require(remaining>0,"response_timeout")
            if connection.sock is not None:connection.sock.settimeout(remaining)
            block=response.read1(min(65536,w.MAX_BYTES+1-size))
            if not block:break
            blocks.append(block);size+=len(block);w.require(size<=w.MAX_BYTES,"response_too_large")
        # A redirect remains a non-success response. Its Location is never used.
        return response.status,b''.join(blocks)
    finally:connection.close()
