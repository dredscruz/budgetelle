// Recovery-flow e2e against LIVE API: envelope encryption + Recovery Key.
const { webcrypto } = require('crypto');
const crypto = webcrypto;
const enc = new TextEncoder(), dec = new TextDecoder();

async function sha256hex(s){ const b=await crypto.subtle.digest('SHA-256',enc.encode(s));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''); }
async function deriveKey(pass,salt){
  const base=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},
    base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']); }
async function encryptJSON(key,obj){ const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(obj)));
  return {iv:btoa(String.fromCharCode(...iv)),ct:btoa(String.fromCharCode(...new Uint8Array(ct)))}; }
async function decryptJSON(key,blob){ const iv=Uint8Array.from(atob(blob.iv),c=>c.charCodeAt(0));
  const ct=Uint8Array.from(atob(blob.ct),c=>c.charCodeAt(0));
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct))); }
async function keyFromB64(b64){ return crypto.subtle.importKey('raw',Uint8Array.from(atob(b64),c=>c.charCodeAt(0)),'AES-GCM',false,['encrypt','decrypt']); }
async function randB64(n){ return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n)))); }
async function wrapB64(b64,kek){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},kek,enc.encode(b64));
  return {iv:btoa(String.fromCharCode(...iv)),ct:btoa(String.fromCharCode(...new Uint8Array(ct)))}; }
async function unwrapB64(w,kek){
  const iv=Uint8Array.from(atob(w.iv),c=>c.charCodeAt(0));
  return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv},kek,Uint8Array.from(atob(w.ct),c=>c.charCodeAt(0)))); }

const BASE='https://budgetelle.vercel.app';
const ok=(n,c)=>console.log((c?'PASS':'FAIL')+'  '+n);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

(async()=>{
  const EM=`recov${Date.now()}@example.com`, PW='startpass1';
  // ---- SIGN-UP: account + recovery hash + envelope doc (as app.js does) ----
  const saltB64=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const hash=await sha256hex(`${EM}:${PW}:${saltB64}`);
  const RK=await randB64(24);                       // personal Recovery Key
  const recovHash=await sha256hex(RK);
  let r=await fetch(BASE+'/api/account',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,salt:saltB64,hash,recovHash})});
  ok('Sign-up registers account + recovery hash',(await r.json()).ok===true);

  const salt=Uint8Array.from(atob(saltB64),c=>c.charCodeAt(0));
  const kek=await deriveKey(PW,salt);
  const DEK=await randB64(32);
  const dekKey=await keyFromB64(DEK);
  const db={entries:[{id:7,date:'2026-08-24',type:'income',category:'Salary',amount:5000}],settings:{idleMin:15}};
  const vault=await encryptJSON(dekKey,db);
  const wrap=await wrapB64(DEK,kek);
  const recovery=await wrapB64(DEK,await keyFromB64(RK));
  const doc=JSON.stringify({fmt:2,wrap,vault,recovery});
  r=await fetch(BASE+'/api/vault',{method:'POST',headers:{'Content-Type':'application/json',
    'bt-email':EM,'bt-salt':saltB64,'bt-hash':hash},body:JSON.stringify({doc})});
  ok('Vault saved in envelope format',(await r.json()).ok===true);
  await sleep(2000);

  // ---- DEVICE B: normal password sign-in restores data ----
  r=await fetch(`${BASE}/api/account?email=${encodeURIComponent(EM)}`);
  const {salt:csaltB64}=await r.json();
  const chash=await sha256hex(`${EM}:${PW}:${csaltB64}`);
  const vr=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':csaltB64,'bt-hash':chash}});
  const {doc:d2}=await vr.json();
  const kekB=await deriveKey(PW,Uint8Array.from(atob(csaltB64),c=>c.charCodeAt(0)));
  const env=JSON.parse(d2);
  const dekB=await unwrapB64(env.wrap,kekB);
  const restored=await decryptJSON(await keyFromB64(dekB),env.vault);
  ok('Password sign-in on new device restores intact data',restored.entries[0].amount===5000&&restored.entries[0].category==='Salary');

  // ---- FORGOT PASSWORD + RECOVERY KEY → data intact under new password ----
  r=await fetch(BASE+'/api/recover',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,recovHash})});
  ok('Recovery-key auth accepts correct key',r.status===200);
  const {doc:rd}=await r.json();
  ok('/api/recover returns the encrypted blob only',rd===doc);
  const renv=JSON.parse(rd);
  const dekR=await unwrapB64(renv.recovery,await keyFromB64(RK));   // client-side unwrap
  const dbR=await decryptJSON(await keyFromB64(dekR),renv.vault);
  ok('Recovery unwraps DEK — full data decrypted locally',dbR.entries[0].amount===5000&&dbR.settings.idleMin===15);

  // re-key under NEW password (what doReset does)
  const nsaltB64=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const nhash=await sha256hex(`${EM}:newpass99:${nsaltB64}`);
  r=await fetch(BASE+'/api/account',{method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,salt:nsaltB64,hash:nhash,oldHash:recovHash})});
  ok('Reset replaces credentials (old-hash guard passes)',(await r.json()).ok===true);
  const nkek=await deriveKey('newpass99',Uint8Array.from(atob(nsaltB64),c=>c.charCodeAt(0)));
  const nwrap=await wrapB64(dekR,nkek);                              // SAME DEK re-wrapped
  const ndoc=JSON.stringify({fmt:2,wrap:nwrap,vault:renv.vault,recovery:renv.recovery});
  r=await fetch(BASE+'/api/vault',{method:'POST',headers:{'Content-Type':'application/json',
    'bt-email':EM,'bt-salt':nsaltB64,'bt-hash':nhash},body:JSON.stringify({doc:ndoc})});
  ok('Same DEK republished under new password',(await r.json()).ok===true);
  await sleep(2000);

  // ---- sign in with NEW password on yet another device — all data there ----
  r=await fetch(`${BASE}/api/account?email=${encodeURIComponent(EM)}`);
  const {salt:s3}=await r.json();
  const h3=await sha256hex(`${EM}:newpass99:${s3}`);
  const v3=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':s3,'bt-hash':h3}});
  const e3=JSON.parse((await v3.json()).doc);
  const final=await decryptJSON(await keyFromB64(await unwrapB64(e3.wrap,await deriveKey('newpass99',Uint8Array.from(atob(s3),c=>c.charCodeAt(0))))),e3.vault);
  ok('NEW password opens the SAME data after recovery',final.entries[0].amount===5000&&final.settings.idleMin===15);

  // wrong recovery key rejected
  r=await fetch(BASE+'/api/recover',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,recovHash:await sha256hex('wrongkey')})});
  ok('Wrong recovery key rejected (401)',r.status===401);
})();
