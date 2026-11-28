"""Private research files and a narrow pipe-only native Keychain adapter."""
import json
import os
from pathlib import Path
import stat
import subprocess
import wpj_protocol as w

HELPER=Path(__file__).resolve().parents[1]/'build/DeviceIdentity/DeviceIdentityTool'


def directory(path,create=False):
    path=Path(path)
    w.require(path.is_absolute() and str(path)==os.path.normpath(path),'absolute_private_path_required')
    # Refuse ancestor symlinks as well as a symlink at the final component.
    for parent in reversed(path.parents):
        w.require(parent.exists() and not parent.is_symlink(),'unsafe_private_parent')
    if create:path.mkdir(mode=0o700,exist_ok=False)
    info=path.lstat()
    w.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'private_directory_required')
    return path


def read(path,maximum=w.MAX_BYTES):
    path=Path(path);directory(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        w.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=maximum,'private_file_required')
        data=f.read(maximum+1);w.require(len(data)<=maximum,'private_file_too_large')
    return data


def write(path,data):
    path=Path(path);directory(path.parent)
    w.require(isinstance(data,bytes) and len(data)<=w.MAX_BYTES,'private_file_too_large')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())


def read_json(path):return w.parse_json(read(path))
def write_json(path,value):write(path,w.encode(value))


class NativeKeys:
    """Each invocation identifies exactly one research namespace/role."""
    def __init__(self,namespace,helper=HELPER):
        self.namespace=w.canonical_uuid(namespace);self.helper=Path(helper)

    def call(self,action,role,data=None):
        w.require(action in ('create','public','sign','delete') and role in ('device','transport'),'invalid_key_action')
        request={'v':1,'action':action,'namespace':self.namespace,'role':role}
        if action=='sign':
            w.require(isinstance(data,bytes) and 0<len(data)<=262144,'invalid_signing_input')
            request['data_base64']=w.b64(data)
        else:w.require(data is None,'unexpected_signing_input')
        # Never put a key, token, challenge or signature on the command line.
        result=subprocess.run([str(self.helper)],input=w.encode(request),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
        value=w.parse_json(result.stdout,1048576)
        w.require(result.returncode==0 and value.get('ok') is True,'native_key_operation_failed')
        w.require(value.get('v')==1 and value.get('action')==action and value.get('namespace')==self.namespace and value.get('role')==role,'native_key_response_mismatch')
        return value

    def create(self,role):
        result=self.call('create',role)
        return self._public(result)

    def public(self,role):return self._public(self.call('public',role))

    @staticmethod
    def _public(result):
        w.require(result.get('public_key_format')=='spki_der','invalid_public_key_format')
        raw=w.unb64(result.get('public_key_base64'));w.public_key(raw)
        return raw

    def sign(self,data):
        result=self.call('sign','device',data)
        w.require(result.get('algorithm')=='RS256','unsupported_native_signature')
        raw=w.unb64(result.get('signature_base64'),256)
        w.require(len(raw)==256,'invalid_native_signature')
        return raw
