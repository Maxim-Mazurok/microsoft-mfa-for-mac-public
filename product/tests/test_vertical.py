"""Cross-component contract checks: extension DOM output -> protocol controller.

All identities are invented; no real credentials, Keychain or network are used.
Native rendering and Safari injection are separate verification gates.
"""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

PRODUCT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCT / "service"))
from controller import Controller
from state import StateStore

DOM_SCRIPT = r"""
const fs = require('node:fs');
const {JSDOM} = require('./product/SafariExtension/node_modules/jsdom');
const core = require('./product/SafariExtension/Resources/core.js');
const input = JSON.parse(fs.readFileSync(0,'utf8'));
const dom = new JSDOM('<div id="displayName"></div><div id="idRichContext_DisplaySign"></div><div id="appDisplayName">Synthetic app</div>');
dom.window.HTMLElement.prototype.getClientRects = function(){return [this.getBoundingClientRect()]};
dom.window.document.querySelector('#displayName').textContent=input.account;
dom.window.document.querySelector('#idRichContext_DisplaySign').textContent='42';
const page=core.readPage(dom.window.document,{account:input.account,session_id:input.session_id,number:'42'});
if (!page) process.exit(2);
const event={version:1,kind:'challenge',event_id:input.event_id,tab_id:'synthetic-tab',document_id:'synthetic-document',origin:'https://login.microsoftonline.com',observed_at:Date.now()/1000,focused:true,...page};
if (!core.validEvent(event)) process.exit(3);
process.stdout.write(JSON.stringify(event));
"""


class VerticalContract(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name).resolve(), synthetic=True)
        self.events = []
        self.controller = Controller(self.store, self.events.append, synthetic=True)
        await self.command("configure", credentials=None, settings={"automatic": True})
        await self.command("session_lock", locked=False)
        self.fields = {"guid": str(uuid.uuid4()), "username": "synthetic@example.invalid", "sasSessionId": str(uuid.uuid4()),
                       "expiration": str(int(time.time()) + 90), "firstEntropyChallenge": "10", "secondEntropyChallenge": "20",
                       "thirdEntropyChallenge": "30", "isAppLockRequired": "no",
                       "authDetails": json.dumps({"ApplicationDisplayName": "Synthetic app"})}

    async def asyncTearDown(self):
        await self.command("shutdown")
        self.store.close(); self.temp.cleanup()

    async def command(self, command, **fields):
        await self.controller.command({"version": 1, "command": command, **fields})

    async def settle(self):
        await asyncio.sleep(0)
        if self.controller.approval_tasks:
            await asyncio.gather(*self.controller.approval_tasks)

    async def browser(self, **override):
        context = {"account": self.fields["username"], "session_id": self.fields["sasSessionId"], "event_id": uuid.uuid4().hex, **override}
        result = await asyncio.to_thread(subprocess.run, ["rtk", "proxy", "node", "-e", DOM_SCRIPT], cwd=PRODUCT.parent,
                                input=json.dumps(context), text=True, capture_output=True, timeout=10, check=True)
        return json.loads(result.stdout)

    def outcomes(self):
        return [event["result"] for event in self.events if event["event"] == "outcome"]

    async def test_browser_dom_contract_automatically_accepts_exact_request_once(self):
        event = await self.browser()
        await self.controller.add_request(self.fields, "https://example.invalid")
        await self.command("browser_event", browser=event)
        await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])
        await self.command("browser_event", browser=event)
        await self.controller.add_request(self.fields, "https://example.invalid")
        await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])

    async def test_same_dom_number_different_session_does_not_approve(self):
        await self.command("browser_event", browser=await self.browser(session_id=str(uuid.uuid4())))
        await self.controller.add_request(self.fields, "https://example.invalid")
        await self.settle()
        self.assertFalse(self.outcomes())

    async def test_same_dom_number_different_account_does_not_approve(self):
        await self.command("browser_event", browser=await self.browser(account="another@example.invalid"))
        await self.controller.add_request(self.fields, "https://example.invalid")
        await self.settle()
        self.assertFalse(self.outcomes())

    async def test_dom_withdrawal_cancels_pending_system_verification(self):
        self.fields["isAppLockRequired"] = "yes"
        event = await self.browser()
        await self.command("browser_event", browser=event)
        item = await self.controller.add_request(self.fields, "https://example.invalid")
        self.assertTrue(item.ticket)
        await self.command("browser_event", browser={key: value for key, value in {
            **event, "kind": "withdraw", "event_id": uuid.uuid4().hex, "observed_at": time.time(), "focused": False
        }.items() if key not in ("number", "account", "application", "session_id", "request_id", "flow", "remote_session_hash")})
        self.assertIsNone(item.ticket)
        await self.settle()
        self.assertFalse(self.outcomes())


if __name__ == "__main__": unittest.main()
