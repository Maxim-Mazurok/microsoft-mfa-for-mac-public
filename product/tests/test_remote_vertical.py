"""Synthetic GetOneTimeCode -> real Safari scripts -> controller/correlation.

No research input, protocol credential, Keychain or network is used.
"""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

PRODUCT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCT / "service"))
from controller import Controller
from state import StateStore
import remotengc

SCRIPT = r"""
const fs=require('fs'),vm=require('vm'),{randomUUID,webcrypto}=require('crypto');
const {JSDOM}=require('./product/SafariExtension/node_modules/jsdom');
const core=require('./product/SafariExtension/Resources/core.js');
const input=JSON.parse(fs.readFileSync(0,'utf8')), handlers={},captured=[],stored={};
const listen=name=>({addListener:fn=>handlers[name]=fn});
const browser={storage:{session:{setAccessLevel:async()=>{},get:async()=>stored,set:async x=>Object.assign(stored,x)}},runtime:{onMessage:listen('message'),getURL:()=> 'safari-web-extension://synthetic/',sendNativeMessage:async(_id,m)=>{captured.push(m);return {ok:true,status:'delivered'};}},tabs:{get:async()=>({active:true,windowId:1,url:'https://login.microsoftonline.com/common/login'}),query:async()=>[],sendMessage:async()=>{},onRemoved:listen('removed'),onUpdated:listen('updated'),onActivated:listen('activated')},windows:{get:async()=>({focused:true}),onFocusChanged:listen('focus')}};
vm.runInNewContext(fs.readFileSync('./product/SafariExtension/Resources/background.js','utf8'),{browser,MFAMac:core,crypto:{randomUUID},Date,Set,Map,Object,Promise});
const dom=new JSDOM('<span id="displayName"></span><span id="idRemoteNGC_DisplaySign">42</span><span id="appDisplayName">Synthetic app</span>',{url:'https://login.microsoftonline.com/common/login',runScripts:'outside-only',pretendToBeVisual:true});
const w=dom.window;w.document.getElementById('displayName').textContent=input.account;w.document.hasFocus=()=>true;w.HTMLElement.prototype.getClientRects=function(){return [{width:100,height:20}]};
w.TextDecoder=TextDecoder;w.TextEncoder=TextEncoder;Object.defineProperty(w.crypto,'subtle',{value:webcrypto.subtle});
w.$Config={sPOST_Username:input.account,oGetCredTypeResult:{Credentials:{HasRemoteNGC:true,RemoteNgcParams:{SessionIdentifier:'SyntheticInitialConfig_'.repeat(40)}}}};
w.postMessage=data=>queueMicrotask(()=>w.dispatchEvent(new w.MessageEvent('message',{source:w,origin:w.location.origin,data})));
w.browser={runtime:{sendMessage:m=>handlers.message(m,{tab:{id:7},frameId:0,url:w.location.origin+'/common/login'}),onMessage:{addListener:()=>{}}}};
w.fetch=async()=>{const r=new Response(JSON.stringify({RemoteNgcParams:{SessionIdentifier:input.session,Entropy:42}}));Object.defineProperty(r,'url',{value:w.location.origin+'/common/GetOneTimeCode'});return r;};
for(const file of ['page-hook.js','core.js','content.js'])w.eval(fs.readFileSync('./product/SafariExtension/Resources/'+file,'utf8'));
(async()=>{await new Promise(r=>setTimeout(r,20));if(input.current)await w.fetch(w.location.origin+'/common/GetOneTimeCode');await new Promise(r=>setTimeout(r,80));const events=captured.filter(x=>x.command==='browser_event'&&x.browser.kind==='challenge').map(x=>x.browser);const event=events.findLast(e=>input.current?!!e.remote_session_hash:!e.remote_session_hash);if(!event)throw Error('synthetic_capture_missing');process.stdout.write(JSON.stringify(event));w.dispatchEvent(new w.Event('pagehide'));await new Promise(r=>setTimeout(r,10));w.close();})().catch(()=>{process.exitCode=2;w.close();});
"""


class RemoteVertical(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name).resolve(), synthetic=True)
        self.events, self.sent = [], []

        async def forbidden(*args):
            self.sent.append(True)
            raise AssertionError("network forbidden")

        self.controller = Controller(self.store, self.events.append, synthetic=True, sender=forbidden)
        await self.command("configure", credentials=None, settings={"automatic": True})
        await self.command("session_lock", locked=False)
        self.account = SimpleNamespace(username="synthetic@example.invalid", tenant_id="11111111-2222-3333-4444-555555555555", object_id="66666666-7777-8888-9999-aaaaaaaaaaaa")
        self.controller.credentials = SimpleNamespace(account=self.account)
        self.session = "SyntheticCurrentRemoteSession_" * 30

    async def asyncTearDown(self):
        await self.command("shutdown")
        self.store.close()
        self.temp.cleanup()

    async def command(self, name, **fields):
        await self.controller.command({"version": 1, "command": name, **fields})

    async def browser(self, current):
        result = await asyncio.to_thread(subprocess.run, ["rtk", "proxy", "node", "-e", SCRIPT],
            cwd=PRODUCT.parent, input=json.dumps({"account": self.account.username, "session": self.session, "current": current}),
            capture_output=True, text=True, timeout=10, check=True)
        return json.loads(result.stdout)

    def push(self, session):
        return {"source": "SAS", "type": "NGC", "sessiontype": "ngc", "sessionid": session,
            "tenantid": self.account.tenant_id, "userobjectidhash": remotengc.object_id_hash(self.account.object_id),
            "requesttime": str(int(time.time())), "expirationtime": str(int(time.time()) + 60),
            "firstentropychallenge": "10", "secondentropychallenge": "20", "thirdentropychallenge": "30",
            "authdetails": json.dumps({"ApplicationDisplayName": "Synthetic app"})}

    async def test_initial_config_is_detection_only_never_approval(self):
        event = await self.browser(False)
        self.assertEqual(event["remote_session_hash"], "")
        await self.command("browser_event", browser=event)
        self.assertEqual(self.controller.ngc_status, "session_binding_unavailable")
        self.assertFalse(self.controller.pending)
        self.assertFalse(self.sent)

    async def test_current_response_matches_real_correlation_but_requires_registration(self):
        event = await self.browser(True)
        self.assertEqual(event["remote_session_hash"], remotengc.remote_session_hash(self.session))
        await self.command("browser_event", browser=event)
        await self.controller.receive_ngc(self.push(self.session))
        request_id, _ = next(iter(self.controller.ngc_candidates.values()))
        self.assertIsNotNone(self.controller.engine.match(request_id, time.time()))
        self.assertEqual(self.controller.ngc_status, "registration_required")
        self.assertFalse(self.controller.pending)
        self.assertFalse(self.sent)

    async def test_same_number_different_remote_session_never_matches(self):
        await self.command("browser_event", browser=await self.browser(True))
        await self.controller.receive_ngc(self.push(self.session + "Different"))
        request_id, _ = next(iter(self.controller.ngc_candidates.values()))
        self.assertIsNone(self.controller.engine.match(request_id, time.time()))
        self.assertFalse(self.sent)


if __name__ == "__main__":
    unittest.main()
