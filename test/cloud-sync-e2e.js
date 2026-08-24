// End-to-end test against the LIVE API, replicating app.js crypto exactly.
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

const BASE='https://budgetelle.vercel.app';
const ok=(name,c)=>console.log((c?'PASS':'FAIL')+'  '+name);

(async()=>{
  const EM=`e2e${Date.now()}@example.com`, PW='hunter22';
  // ---- DEVICE A: sign up (as signUp() does) ----
  let salt=crypto.getRandomValues(new Uint8Array(16));
  const saltB64=btoa(String.fromCharCode(...salt));
  const hash=await sha256hex(`${EM}:${PW}:${saltB64}`);
  let r=await fetch(BASE+'/api/account',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,salt:saltB64,hash})});
  ok('A: signup registers cloud account',(await r.json()).ok===true);

  // enter vault, add data, persist mirrors encrypted blob
  let key=await deriveKey(PW,salt);
  let db={entries:[{id:1,date:'2026-08-24',type:'expense',category:'Groceries',amount:42.5}],settings:{}};
  let blob=JSON.stringify(await encryptJSON(key,db));
  r=await fetch(BASE+'/api/vault',{method:'POST',headers:{'Content-Type':'application/json',
    'bt-email':EM,'bt-salt':saltB64,'bt-hash':hash},body:JSON.stringify({doc:blob})});
  ok('A: save syncs encrypted vault to cloud',(await r.json()).ok===true);

  // ---- DEVICE B: fresh device, no local record — sign in ----
  r=await fetch(`${BASE}/api/account?email=${encodeURIComponent(EM)}`);
  const {salt:csaltB64}=await r.json();
  const csalt=Uint8Array.from(atob(csaltB64),c=>c.charCodeAt(0));
  const chash=await sha256hex(`${EM}:${PW}:${csaltB64}`);
  const vr=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':csaltB64,'bt-hash':chash}});
  const vj=await vr.json();
  ok('B: cloud accepts correct password',vj.doc===blob);
  key=await deriveKey(PW,csalt);
  const restored=await decryptJSON(key,JSON.parse(vj.doc));
  ok('B: vault decrypts intact — data where they left off',restored.entries[0].amount===42.5&&restored.entries[0].category==='Groceries');

  // wrong password rejected
  const badhash=await sha256hex(`${EM}:wrongpass:${csaltB64}`);
  r=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':csaltB64,'bt-hash':badhash}});
  ok('B: wrong password rejected (401)',r.status===401);

  // ---- PASSWORD RESET from Device B, then sign in on Device C ----
  const nsaltB64=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const nhash=await sha256hex(`${EM}:newpass9:${nsaltB64}`);
  r=await fetch(BASE+'/api/account',{method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,salt:nsaltB64,hash:nhash,oldHash:chash})});
  ok('Reset: old credential authorizes new one',(await r.json()).ok===true);
  // app clears the stale old-key blob right after reset
  await fetch(BASE+'/api/vault',{method:'POST',headers:{'Content-Type':'application/json','bt-email':EM,'bt-salt':nsaltB64,'bt-hash':nhash},body:JSON.stringify({doc:''})});
  await new Promise(r2=>setTimeout(r2,2000));
  r=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':nsaltB64,'bt-hash':nhash}});
  ok('C: vault GET status after reset',r.status===200);
  const doc2=await r.json();
  ok('C: stale old-key blob cleared after reset',doc2.doc===null||doc2.doc==='');
  key=await deriveKey('newpass9',Uint8Array.from(atob(nsaltB64),c=>c.charCodeAt(0)));
  // blob was cleared by reset; a fresh save with the new password then round-trips
  const freshDB={entries:[{id:2,amount:99}],settings:{}};
  const fblob=JSON.stringify(await encryptJSON(key,freshDB));
  r=await fetch(BASE+'/api/vault',{method:'POST',headers:{'Content-Type':'application/json',
    'bt-email':EM,'bt-salt':nsaltB64,'bt-hash':nhash},body:JSON.stringify({doc:fblob})});
  ok('C: re-saves vault under new password',(await r.json()).ok===true);
  r=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':nsaltB64,'bt-hash':nhash}});
  const back=await decryptJSON(key,JSON.parse((await r.json()).doc));
  ok('C: data saved after reset is intact on next login',back.entries[0].amount===99);
  // old password no longer works
  r=await fetch(BASE+'/api/vault',{headers:{'bt-email':EM,'bt-salt':csaltB64,'bt-hash':chash}});
  ok('C: old password dead after reset',[401,403].includes(r.status));
  // reset without oldHash cannot hijack an existing account
  r=await fetch(BASE+'/api/account',{method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:EM,salt:nsaltB64,hash:nhash})});
  ok('Security: account takeover without old credential blocked',r.status===403);
})();
