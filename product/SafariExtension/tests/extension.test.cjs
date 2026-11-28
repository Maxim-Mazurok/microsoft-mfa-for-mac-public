"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {randomUUID,createHash,webcrypto} = require("node:crypto");
const {JSDOM} = require("jsdom");
const core = require("../Resources/core.js");
const resources = path.join(__dirname, "../Resources");
const session = "11111111-2222-4333-8444-555555555555";
const base = {version:1, kind:"challenge", event_id:"event", tab_id:"tab", document_id:"doc", origin:"https://login.microsoftonline.com", observed_at:100, number:"42", account:"user@example.invalid", application:"Synthetic app", session_id:session, request_id:"", focused:true};
const delay = () => new Promise(resolve => setTimeout(resolve, 20));
function page(html) {
  const dom = new JSDOM(html, {url:"https://login.microsoftonline.com/common/login", runScripts:"outside-only", pretendToBeVisual:true});
  dom.window.HTMLElement.prototype.getClientRects = function() { return this.hidden || this.style.display === "none" ? [] : [{width:100,height:30}]; };
  return dom;
}
test("origin allowlist rejects lookalikes, custom ports and credentials", () => {
  assert.equal(core.origin("https://login.microsoftonline.com/common?secret=ignored"), base.origin);
  for(const url of ["http://login.microsoftonline.com", "https://login.microsoftonline.com.evil.invalid", "https://login.microsoftonline.com:8443", "https://u:p@login.microsoftonline.com", "file:///tmp/login"]) assert.equal(core.origin(url), null);
});
test("canonical events require account plus exact UUID, reject extra/secret fields", () => {
  assert.equal(core.validEvent(base, 100), true);
  for(const patch of [{account:""}, {session_id:""}, {session_id:"correlation-fuzzy"}, {flowToken:"secret"}, {flow:null}, {observed_at:NaN}, {observed_at:-21}, {observed_at:106}, {number:"142"}, {version:true}, {focused:1}]) assert.equal(core.validEvent({...base,...patch}, 100),false);
});
test("DOM selector requires unambiguous visible number, account and selected shared session", () => {
  const dom=page('<span id="idRichContext_DisplaySign">42</span><span id="displayName">USER@example.invalid</span><span id="appDisplayName">Synthetic app</span>');
  assert.equal(core.readPage(dom.window.document,{session_id:session}).number,"42");
  assert.equal(core.readPage(dom.window.document,{}),null);
  assert.equal(core.readPage(dom.window.document,{session_id:session, account:"other@example.invalid"}),null);
  assert.equal(core.readPage(dom.window.document,{session_id:session, number:"43"}),null);
  dom.window.document.querySelector("#idRichContext_DisplaySign").hidden=true;
  assert.equal(core.readPage(dom.window.document,{session_id:session}),null);
  dom.window.close();
});
test("unrelated page numbers and ambiguous duplicate selectors never match", () => {
  const dom=page('<p>42</p><span id="displayName">user@example.invalid</span>');
  assert.equal(core.readPage(dom.window.document,{session_id:session}),null);
  dom.window.document.body.insertAdjacentHTML("beforeend",'<span id="idRichContext_DisplaySign">42</span><span id="idRichContext_DisplaySign">43</span>');
  assert.equal(core.readPage(dom.window.document,{session_id:session}),null);
  dom.window.close();
});
test("conflicting visible accounts cannot fall back to main-world account metadata",()=>{
  const dom=page('<span id="idRichContext_DisplaySign">42</span><span id="displayName">first@example.invalid</span><span data-testid="user-display-name">second@example.invalid</span>');
  assert.equal(core.readPage(dom.window.document,{session_id:session,account:"first@example.invalid"}),null);dom.window.close();
});
test("hidden styles and hidden ancestors cannot supply a number",()=>{
  for(const attributes of ['style="visibility:hidden"','style="opacity:0"','hidden','aria-hidden="true"']){
    const dom=page(`<div ${attributes}><span id="idRichContext_DisplaySign">42</span></div><span id="displayName">user@example.invalid</span>`);
    assert.equal(core.readPage(dom.window.document,{session_id:session}),null);dom.window.close();
  }
});
test("MAIN hook exports only selected response fields and leaves fetch response intact", async () => {
  const dom=page(""); const w=dom.window; const messages=[];
  w.$Config={sPOST_Username:"USER@example.invalid", sFT:"do-not-export"};
  w.TextDecoder=TextDecoder; w.TextEncoder=TextEncoder;
  const response=new Response(JSON.stringify({SessionId:session, Entropy:42, FlowToken:"do-not-export", Ctx:"do-not-export"}));
  Object.defineProperty(response,"url",{value:"https://login.microsoftonline.com/common/SAS/BeginAuth"});
  let calls=0; w.fetch=()=>{calls++;return Promise.resolve(response);};
  w.postMessage=(data)=>messages.push(data);
  w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));
  assert.equal(await w.fetch("https://login.microsoftonline.com/common/SAS/BeginAuth"),response);
  await delay();
  assert.equal(calls,1); assert.equal(messages.length,1);
  assert.deepEqual(Object.keys(messages[0]).sort(),["account","flow","marker","number","observed_at","session_id"]);
  assert.equal(messages[0].session_id,session); assert.equal(messages[0].number,"42");
  assert.equal(JSON.stringify(messages).includes("do-not-export"),false);
  assert.equal((await response.json()).FlowToken,"do-not-export");
  dom.window.close();
});
test("MAIN hook ignores arbitrary endpoints and invalid session IDs", async () => {
  for(const [url,id] of [["https://login.microsoftonline.com/common/SAS/EndAuth",session],["https://other.invalid/common/SAS/BeginAuth",session],["https://login.microsoftonline.com/common/SAS/BeginAuth","not-a-uuid"]]) {
    const dom=page(""); const w=dom.window; const messages=[]; w.TextDecoder=TextDecoder;
    const response=new Response(JSON.stringify({SessionId:id,Entropy:42})); Object.defineProperty(response,"url",{value:url});
    w.fetch=()=>Promise.resolve(response); w.postMessage=data=>messages.push(data);
    w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8")); await w.fetch(url); await delay();
    assert.equal(messages.length,0); dom.window.close();
  }
});
test("MAIN XHR hook selects only supported successful response context",()=>{
  const dom=page("");const w=dom.window,messages=[];
  class FakeXHR {
    constructor(){this.listeners=[];this.status=200;this.responseType="json";this.response={SessionId:session,Entropy:42,FlowToken:"not-exported"};}
    addEventListener(name,callback){if(name==="load")this.listeners.push(callback);}
    open(_method,url){this.responseURL=new URL(url,w.location.href).href;}
    complete(){for(const callback of this.listeners)callback();}
  }
  w.XMLHttpRequest=FakeXHR;w.fetch=()=>{throw Error("No network expected");};w.postMessage=data=>messages.push(data);
  w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));
  const xhr=new w.XMLHttpRequest();xhr.open("POST","/common/SAS/BeginAuth");xhr.complete();
  assert.equal(messages.length,1);assert.equal(messages[0].session_id,session);assert.equal(JSON.stringify(messages).includes("not-exported"),false);
  const rejected=new w.XMLHttpRequest();rejected.status=403;rejected.open("POST","/common/SAS/BeginAuth");rejected.complete();
  const other=new w.XMLHttpRequest();other.open("POST","/common/SAS/EndAuth");other.complete();assert.equal(messages.length,1);dom.window.close();
});
const opaqueRemote="SyntheticOpaqueRemoteSession_".repeat(30);
const remoteHash=createHash("sha256").update("remote_ngc\0"+opaqueRemote,"utf8").digest("hex");
test("RemoteNGC has separate visible detection and cannot reuse classic UUID context",()=>{
  const dom=page('<span id="idRemoteNGC_DisplaySign">42</span><span id="displayName">user@example.invalid</span>');
  assert.equal(core.detectFlow(dom.window.document),"remote_ngc");
  assert.equal(core.readPage(dom.window.document,{session_id:session,account:base.account}),null);
  const detected=core.readPage(dom.window.document,{flow:"remote_ngc",account:base.account,remote_session_hash:""});
  assert.equal(detected.flow,"remote_ngc");assert.equal(detected.session_id,"");assert.equal(detected.request_id,"");assert.equal(detected.remote_session_hash,"");
  const correlated=core.readPage(dom.window.document,{flow:"remote_ngc",account:base.account,remote_session_hash:remoteHash,number:"42"});assert.equal(correlated.remote_session_hash,remoteHash);
  for(const number of ["", "43"]) assert.equal(core.readPage(dom.window.document,{flow:"remote_ngc",account:base.account,remote_session_hash:remoteHash,number}),null);
  dom.window.document.body.insertAdjacentHTML("beforeend",'<span id="idRichContext_DisplaySign">42</span>');assert.equal(core.detectFlow(dom.window.document),"");assert.equal(core.readPage(dom.window.document,{flow:"remote_ngc",account:base.account}),null);dom.window.close();
});
test("canonical RemoteNGC events allow detection/hash only and reject cross-flow fields",()=>{
  const remote={...base,flow:"remote_ngc",session_id:"",request_id:"",remote_session_hash:""};
  assert.equal(core.validEvent(remote,100),true);assert.equal(core.validEvent({...remote,remote_session_hash:remoteHash},100),true);
  for(const patch of [{flow:"unknown"},{flow:true},{session_id:session},{request_id:session},{remote_session_hash:remoteHash.toUpperCase()},{remote_session_hash:opaqueRemote},{remote_session_id:opaqueRemote}]) assert.equal(core.validEvent({...remote,...patch},100),false);
  assert.equal(core.validEvent({...base,flow:"classic_mfa",remote_session_hash:remoteHash},100),false);
});
test("initial RemoteNGC config is detection-only despite opaque identifier and telemetry UUID",async()=>{
  const dom=page("");const w=dom.window,messages=[];
  w.$Config={sPOST_Username:base.account,sessionId:session,oGetCredTypeResult:{Credentials:{HasRemoteNGC:true,RemoteNgcParams:{SessionIdentifier:opaqueRemote,DefaultType:1,Application:session}}}};
  w.fetch=()=>{throw Error("No network expected");};w.postMessage=data=>messages.push(data);w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));await delay();
  const remote=messages.find(m=>m.flow==="remote_ngc");assert.ok(remote);assert.equal(remote.remote_session_hash,"");assert.equal(remote.session_id,"");assert.equal(JSON.stringify(messages).includes(opaqueRemote),false);assert.equal(JSON.stringify(messages).includes(session),false);dom.window.close();
});
test("current GetOneTimeCode response hashes exact opaque ID and exports no raw credentials",async()=>{
  const dom=page("");const w=dom.window,messages=[];w.TextDecoder=TextDecoder;w.TextEncoder=TextEncoder;
  Object.defineProperty(w.crypto,"subtle",{value:webcrypto.subtle});w.$Config={sPOST_Username:base.account};
  const response=new Response(JSON.stringify({RemoteNgcParams:{SessionIdentifier:opaqueRemote,Entropy:42,Application:session},FlowToken:"do-not-export",SessionId:session}));
  Object.defineProperty(response,"url",{value:base.origin+"/common/GetOneTimeCode"});w.fetch=()=>Promise.resolve(response);w.postMessage=data=>messages.push(data);
  w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));assert.equal(await w.fetch(base.origin+"/common/GetOneTimeCode"),response);await delay();
  const m=messages.find(m=>m.flow==="remote_ngc"&&m.remote_session_hash);assert.equal(m.remote_session_hash,remoteHash);assert.equal(m.session_id,"");assert.equal(m.number,"42");
  assert.equal(JSON.stringify(messages).includes(opaqueRemote),false);assert.equal(JSON.stringify(messages).includes("do-not-export"),false);assert.equal(JSON.stringify(messages).includes(session),false);assert.ok((await response.json()).RemoteNgcParams.SessionIdentifier===opaqueRemote);dom.window.close();
});
test("RemoteNGC response with missing entropy/oversized ID/wrong endpoint yields no hash",async()=>{
  const cases=[{params:{SessionIdentifier:opaqueRemote},path:"/common/GetOneTimeCode"},{params:{SessionIdentifier:"a".repeat(16385),Entropy:42},path:"/common/GetOneTimeCode"},{params:{SessionIdentifier:opaqueRemote,Entropy:42},path:"/common/GetCredentialType"},{params:{SessionIdentifier:opaqueRemote,Entropy:42},path:"/common/DeviceCodeStatus"}];
  for(const {params,path:endpointPath} of cases){const dom=page("");const w=dom.window,messages=[];w.TextDecoder=TextDecoder;w.TextEncoder=TextEncoder;Object.defineProperty(w.crypto,"subtle",{value:webcrypto.subtle});const response=new Response(JSON.stringify({RemoteNgcParams:params}));Object.defineProperty(response,"url",{value:base.origin+endpointPath});w.fetch=()=>Promise.resolve(response);w.postMessage=data=>messages.push(data);w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));await w.fetch(base.origin+endpointPath);await delay();assert.equal(messages.filter(m=>m.remote_session_hash).length,0);dom.window.close();}
});
test("RemoteNGC invalidates at request start and ignores older same-number responses",async()=>{
  const dom=page("");const w=dom.window,messages=[],resolvers=[];w.TextDecoder=TextDecoder;w.TextEncoder=TextEncoder;Object.defineProperty(w.crypto,"subtle",{value:webcrypto.subtle});w.$Config={sPOST_Username:base.account};
  w.fetch=()=>new Promise(resolve=>resolvers.push(resolve));w.postMessage=data=>messages.push(data);w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));
  const first=w.fetch(base.origin+"/common/GetOneTimeCode"),second=w.fetch(base.origin+"/common/GetOneTimeCode");
  assert.equal(messages.filter(m=>m.marker==="microsoft-mfa-mac-context-invalidated-v1").length,2);
  function response(id){const r=new Response(JSON.stringify({RemoteNgcParams:{SessionIdentifier:id,Entropy:42}}));Object.defineProperty(r,"url",{value:base.origin+"/common/GetOneTimeCode"});return r;}
  const newer=opaqueRemote+"New";resolvers[1](response(newer));await second;await delay();resolvers[0](response(opaqueRemote));await first;await delay();
  const hashes=messages.filter(m=>m.remote_session_hash).map(m=>m.remote_session_hash);assert.deepEqual(hashes,[createHash("sha256").update("remote_ngc\0"+newer).digest("hex")]);
  const third=w.fetch(base.origin+"/common/GetOneTimeCode");assert.equal(messages.at(-1).marker,"microsoft-mfa-mac-context-invalidated-v1");resolvers[2](response("invalid"));await third;await delay();
  w.dispatchEvent(new w.MessageEvent("message",{source:w,origin:w.location.origin,data:{marker:"microsoft-mfa-mac-context-request-v1"}}));assert.equal(messages.filter(m=>m.remote_session_hash).length,1);dom.window.close();
});
test("RemoteNGC response cannot be rebound to a changed account or navigation",async()=>{
  for(const change of ["account","navigation"]){const dom=page("");const w=dom.window,messages=[];let resolve;w.TextDecoder=TextDecoder;w.TextEncoder=TextEncoder;Object.defineProperty(w.crypto,"subtle",{value:webcrypto.subtle});w.$Config={sPOST_Username:base.account};w.fetch=()=>new Promise(r=>resolve=r);w.postMessage=data=>messages.push(data);w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));const pending=w.fetch(base.origin+"/common/GetOneTimeCode");if(change==="account")w.$Config.sPOST_Username="other@example.invalid";else w.dispatchEvent(new w.Event("popstate"));const r=new Response(JSON.stringify({RemoteNgcParams:{SessionIdentifier:opaqueRemote,Entropy:42}}));Object.defineProperty(r,"url",{value:base.origin+"/common/GetOneTimeCode"});resolve(r);await pending;await delay();assert.equal(messages.filter(m=>m.remote_session_hash).length,0);dom.window.close();}
});
test("RemoteNGC XHR send binds generation without reading request body",async()=>{
  const dom=page("");const w=dom.window,messages=[];w.TextEncoder=TextEncoder;Object.defineProperty(w.crypto,"subtle",{value:webcrypto.subtle});w.$Config={sPOST_Username:base.account};
  class FakeXHR {constructor(){this.listeners=[];this.status=200;this.responseType="json";}addEventListener(name,fn){if(name==="load")this.listeners.push(fn);}open(_method,url){this.responseURL=new URL(url,w.location.href).href;}send(_body){}complete(){for(const fn of this.listeners)fn();}}
  w.XMLHttpRequest=FakeXHR;w.fetch=()=>{throw Error("unused");};w.postMessage=data=>messages.push(data);w.eval(fs.readFileSync(path.join(resources,"page-hook.js"),"utf8"));
  const first=new w.XMLHttpRequest(),second=new w.XMLHttpRequest();for(const xhr of [first,second]){xhr.open("POST","/common/GetOneTimeCode");xhr.send(new Proxy({},{get(){throw Error("request body must stay untouched");}}));}
  second.response={RemoteNgcParams:{SessionIdentifier:opaqueRemote+"Newest",Entropy:42}};second.complete();await delay();first.response={RemoteNgcParams:{SessionIdentifier:opaqueRemote,Entropy:42}};first.complete();await delay();
  assert.deepEqual(messages.filter(m=>m.remote_session_hash).map(m=>m.remote_session_hash),[createHash("sha256").update("remote_ngc\0"+opaqueRemote+"Newest").digest("hex")]);dom.window.close();
});
test("content observer deduplicates, retains initial capture across system focus, withdraws hidden tab", async () => {
  const dom=page('<span id="idRichContext_DisplaySign">42</span><span id="displayName">user@example.invalid</span>');
  const w=dom.window; let focused=true, visible="visible"; const messages=[];
  w.document.hasFocus=()=>focused; Object.defineProperty(w.document,"visibilityState",{get:()=>visible});
  w.browser={runtime:{sendMessage:async m=>{messages.push(m);return {status:"delivered"};},onMessage:{addListener:()=>{}}}};
  w.eval(fs.readFileSync(path.join(resources,"core.js"),"utf8")); w.eval(fs.readFileSync(path.join(resources,"content.js"),"utf8"));
  w.dispatchEvent(new w.MessageEvent("message",{source:w,origin:w.location.origin,data:{marker:"microsoft-mfa-mac-selected-context-v1",session_id:session,number:"42",account:"user@example.invalid",observed_at:Date.now()/1000}})); await delay();
  assert.equal(messages.filter(m=>m.kind==="challenge").length,1);
  w.document.querySelector("#displayName").textContent="user@example.invalid"; await delay();
  assert.equal(messages.filter(m=>m.kind==="challenge").length,1);
  focused=false;w.dispatchEvent(new w.Event("blur"));await delay();assert.equal(messages.length,1);
  visible="hidden";w.document.dispatchEvent(new w.Event("visibilitychange"));await delay();
  assert.equal(messages.at(-1).kind,"withdraw");w.dispatchEvent(new w.Event("pagehide"));await delay();dom.window.close();
});
test("content hook refuses spoofed origins and old selected metadata", async () => {
  const dom=page('<span id="idRichContext_DisplaySign">42</span><span id="displayName">user@example.invalid</span>'); const w=dom.window;const messages=[];
  w.document.hasFocus=()=>true;w.browser={runtime:{sendMessage:async m=>messages.push(m),onMessage:{addListener:()=>{}}}};
  w.eval(fs.readFileSync(path.join(resources,"core.js"),"utf8"));w.eval(fs.readFileSync(path.join(resources,"content.js"),"utf8"));
  for(const [origin,timestamp] of [["https://evil.invalid",Date.now()/1000],[w.location.origin,Date.now()/1000-100]]) w.dispatchEvent(new w.MessageEvent("message",{source:w,origin,data:{marker:"microsoft-mfa-mac-selected-context-v1",session_id:session,number:"42",account:"user@example.invalid",observed_at:timestamp}}));
  await delay();assert.equal(messages.length,0);w.dispatchEvent(new w.Event("pagehide"));await delay();dom.window.close();
});
test("content observer sends RemoteNGC detection separately, then current-session hash",async()=>{
  const dom=page('<span id="idRemoteNGC_DisplaySign">42</span><span id="displayName">user@example.invalid</span>');const w=dom.window,messages=[];
  w.document.hasFocus=()=>true;w.browser={runtime:{sendMessage:async m=>{messages.push(m);return {ok:true,status:"delivered"};},onMessage:{addListener:()=>{}}}};
  w.eval(fs.readFileSync(path.join(resources,"core.js"),"utf8"));w.eval(fs.readFileSync(path.join(resources,"content.js"),"utf8"));
  const selected={marker:"microsoft-mfa-mac-selected-context-v1",flow:"remote_ngc",session_id:"",remote_session_hash:"",number:"",account:base.account,observed_at:Date.now()/1000};
  w.dispatchEvent(new w.MessageEvent("message",{source:w,origin:w.location.origin,data:selected}));await delay();
  assert.equal(messages[0].flow,"remote_ngc");assert.equal(messages[0].remote_session_hash,"");assert.equal(messages[0].session_id,"");
  w.dispatchEvent(new w.MessageEvent("message",{source:w,origin:w.location.origin,data:{...selected,remote_session_hash:remoteHash,number:"42"}}));await delay();
  assert.equal(messages.length,2);assert.equal(messages[1].remote_session_hash,remoteHash);assert.equal(messages[1].request_id,"");
  w.dispatchEvent(new w.Event("pagehide"));await delay();dom.window.close();
});
test("RemoteNGC invalidation and disappearing view revoke old same-number evidence",async()=>{
  const dom=page('<span id="idRemoteNGC_DisplaySign">42</span><span id="displayName">user@example.invalid</span>');const w=dom.window,messages=[];
  w.document.hasFocus=()=>true;w.browser={runtime:{sendMessage:async m=>{messages.push(m);return {ok:true,status:"delivered"};},onMessage:{addListener:()=>{}}}};
  w.eval(fs.readFileSync(path.join(resources,"core.js"),"utf8"));w.eval(fs.readFileSync(path.join(resources,"content.js"),"utf8"));
  const selected={marker:"microsoft-mfa-mac-selected-context-v1",flow:"remote_ngc",session_id:"",remote_session_hash:remoteHash,number:"42",account:base.account,observed_at:Date.now()/1000};
  function emit(data){w.dispatchEvent(new w.MessageEvent("message",{source:w,origin:w.location.origin,data}));}
  emit(selected);await delay();emit({marker:"microsoft-mfa-mac-context-invalidated-v1",flow:"remote_ngc"});await delay();assert.equal(messages.at(-1).kind,"withdraw");
  emit(selected);await delay();w.document.getElementById("idRemoteNGC_DisplaySign").remove();await delay();assert.equal(messages.at(-1).kind,"withdraw");
  const captured=messages.filter(m=>m.kind==="challenge").length;w.document.body.insertAdjacentHTML("beforeend",'<span id="idRemoteNGC_DisplaySign">42</span>');await delay();assert.equal(messages.filter(m=>m.kind==="challenge").length,captured);
  w.dispatchEvent(new w.Event("pagehide"));await delay();dom.window.close();
});
test("content delivery recovers when app starts, using bounded retries and original time",async()=>{
  const dom=page('<span id="idRichContext_DisplaySign">42</span><span id="displayName">user@example.invalid</span>');const w=dom.window;const messages=[],timers=[];
  let available=false;w.document.hasFocus=()=>true;w.setTimeout=(callback,ms)=>{timers.push({callback,ms});return timers.length;};
  w.browser={runtime:{sendMessage:async m=>{messages.push(m);return {ok:available,status:available?"delivered":"app_unavailable"};},onMessage:{addListener:()=>{}}}};
  w.eval(fs.readFileSync(path.join(resources,"core.js"),"utf8"));w.eval(fs.readFileSync(path.join(resources,"content.js"),"utf8"));
  const observed=Date.now()/1000-1;
  w.dispatchEvent(new w.MessageEvent("message",{source:w,origin:w.location.origin,data:{marker:"microsoft-mfa-mac-selected-context-v1",session_id:session,number:"42",account:"user@example.invalid",observed_at:observed}}));await delay();
  assert.equal(messages.length,1);assert.equal(timers[0].ms,2000);available=true;timers[0].callback();await delay();assert.equal(messages.length,2);assert.equal(messages[1].observed_at,observed);assert.equal(timers.length,1);
  w.dispatchEvent(new w.Event("pagehide"));await delay();dom.window.close();
});
function background(sessionStorage = {}) {
  const handlers={},sent=[];let active=true,focused=true,fail=false;
  const listener=name=>({addListener:f=>{handlers[name]=f;}});
  const browser={storage:{session:{setAccessLevel:async()=>{},get:async()=>structuredClone(sessionStorage),set:async data=>Object.assign(sessionStorage,structuredClone(data))}},runtime:{onMessage:listener("message"),getURL:()=>"safari-web-extension://synthetic/",sendNativeMessage:async(_app,message)=>{if(fail)throw Error("private failure");sent.push(message);return {ok:true,status:message.command==="status"?"ready":"delivered"};}},tabs:{get:async id=>({id,active,windowId:1,url:base.origin+"/common/login"}),query:async()=>[],sendMessage:async()=>{},onRemoved:listener("removed"),onUpdated:listener("updated"),onActivated:listener("activated")},windows:{get:async()=>({focused}),onFocusChanged:listener("focus")}};
  vm.runInNewContext(fs.readFileSync(path.join(resources,"background.js"),"utf8"),{browser,MFAMac:core,crypto:{randomUUID},Date,Set,Map,Object,Promise});
  return {handlers,sent,browser,setActive:v=>active=v,setFocused:v=>focused=v,setFail:v=>fail=v};
}
function observation(){const {version,event_id,tab_id,document_id,origin,...p}=base;return {type:"observation",document_nonce:"77777777-8888-4999-aaaa-bbbbbbbbbbbb",...p,observed_at:Date.now()/1000};}
const sender={tab:{id:7},frameId:0,url:base.origin+"/common/login"};
test("background assigns browser identity, deduplicates and withdraws navigation",async()=>{
  const b=background();const m=observation();assert.equal((await b.handlers.message(m,sender)).ok,true);
  await b.handlers.message(m,sender);assert.equal(b.sent.length,1);
  const e=b.sent[0].browser;assert.match(e.tab_id,/^[a-f0-9-]{36}$/);assert.equal(e.origin,base.origin);assert.equal(e.request_id,"");
  b.handlers.updated(7,{status:"loading"});await delay();assert.equal(b.sent[1].browser.kind,"withdraw");
});
test("background forwards RemoteNGC flow/hash but never stores server context in session routing",async()=>{
  const routing={};const b=background(routing);const message={...observation(),flow:"remote_ngc",session_id:"",remote_session_hash:remoteHash};
  assert.equal((await b.handlers.message(message,sender)).ok,true);const event=b.sent[0].browser;
  assert.equal(event.flow,"remote_ngc");assert.equal(event.remote_session_hash,remoteHash);assert.equal(event.session_id,"");
  assert.equal(JSON.stringify(routing).includes(remoteHash),false);assert.equal(JSON.stringify(routing).includes(base.account),false);
});
test("background rejects injected IDs, frames, inactive tabs and arbitrary origins",async()=>{
  const b=background();assert.equal((await b.handlers.message({...observation(),tab_id:"forged"},sender)).ok,false);
  assert.equal((await b.handlers.message(observation(),{...sender,frameId:1})).ok,false);
  assert.equal((await b.handlers.message(observation(),{...sender,url:"https://evil.invalid/"})).ok,false);
  b.setActive(false);assert.equal((await b.handlers.message(observation(),sender)).ok,false);assert.equal(b.sent.length,0);
});
test("native unavailable returns fixed status and browser pages cannot send native commands",async()=>{
  const b=background();b.setFail(true);assert.equal((await b.handlers.message(observation(),sender)).status,"app_unavailable");
  assert.equal((await b.handlers.message({type:"status"},sender)).status,"invalid_message");
  assert.equal((await b.handlers.message({command:"manual_approve"},sender)).status,"invalid_message");
  assert.equal(b.sent.length,0);
});
test("window focus loss retains captured event, but cannot create a fresh one",async()=>{
  const b=background();await b.handlers.message(observation(),sender);b.setFocused(false);b.handlers.focus(-1);await delay();assert.equal(b.sent.length,1);
  const fresh=observation();fresh.document_nonce=randomUUID();assert.equal((await b.handlers.message(fresh,sender)).ok,false);
});
test("background restart restores only local routing and withdraws closed/navigated tabs",async()=>{
  for(const trigger of ["removed","updated"]){
    const sessionStorage={};const first=background(sessionStorage);await first.handlers.message(observation(),sender);
    const local=first.sent[0].browser;const serialized=JSON.stringify(sessionStorage);
    for(const forbidden of [base.account,session,'"number"','"account"','"session_id"','"request_id"']) assert.equal(serialized.includes(forbidden),false);
    const restarted=background(sessionStorage);restarted.handlers[trigger](7,{status:"loading"});await delay();
    assert.equal(restarted.sent.length,1);assert.equal(restarted.sent[0].browser.kind,"withdraw");assert.equal(restarted.sent[0].browser.document_id,local.document_id);
  }
});
test("malformed session storage disables fresh automatic capture without disk fallback",async()=>{
  const b=background({mfa_documents_v1:"invalid"});assert.equal((await b.handlers.message(observation(),sender)).status,"local_io_failure");assert.equal(b.sent.length,0);
});
test("manifest limits hosts and permissions to native messaging and session storage",()=>{
  const m=JSON.parse(fs.readFileSync(path.join(resources,"manifest.json")));
  assert.deepEqual(m.permissions,["nativeMessaging","storage"]);assert.equal(m.host_permissions.length,3);assert.ok(m.host_permissions.every(x=>core.ORIGINS.has(x.slice(0,-2))));
  assert.ok(m.content_scripts.every(x=>x.all_frames===false&&x.run_at==="document_start"));
});
