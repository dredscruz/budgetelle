/* ============ Budgetelle — private, encrypted, local-first finance vault ============ */
'use strict';

/* ---------- crypto helpers (WebCrypto) ---------- */
const enc = new TextEncoder(), dec = new TextDecoder();
async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: btoa(String.fromCharCode(...iv)), ct: btoa(String.fromCharCode(...new Uint8Array(ct))) };
}
async function decryptJSON(key, blob) {
  const iv = Uint8Array.from(atob(blob.iv), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(blob.ct), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(dec.decode(pt));
}
async function sha256hex(s) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ---------- state ---------- */
let SESSION = { key: null, email: null, timer: null };
const CURRENCIES = {
  USD:{s:'$',n:'US Dollar'}, EUR:{s:'€'}, GBP:{s:'£'}, AED:{s:'AED '}, PHP:{s:'₱'},
  INR:{s:'₹'}, JPY:{s:'¥'}, CAD:{s:'C$'}, AUD:{s:'A$'}, SGD:{s:'S$'}, CHF:{s:'CHF '}, SAR:{s:'SAR '}
};
const CATS_EXP = ['Groceries','Dining','Fuel','Utilities','Online','Transport','Health','Education','Rent','Entertainment','Other'];
const CATS_INC = ['Salary','Freelance','Bonus','Investment','Rental','Gift','Refund','Other'];
let DB = null; // decrypted working copy

function blankDB() {
  return {
    profile: { name:'', mobile:'', nickname:'' },
    ultimateGoal: '',
    entries: [],        // {id,date,type:'income'|'expense',category,amount,cur,notes,recurring:false}
    budgets: [],        // {id,month,category,limit}
    recurring: [],      // {id,name,category,amount,freq,next,status}
    snapshots: [],      // {id,month,assets,liabilities,notes}
    goals: [],          // {id,name,target,saved,byDate,monthly}
    assets: [],         // {id,name,category,value,notes}
    insurance: [],      // {id,policy,type,premium,frequency,due}
    documents: [],      // {id,doc,type,number,holder,issued,expiry}
    cards: [],          // {id,name,bank,rules:[{cat,pct}]}
    loans: [],          // {id,name,lender,principal,rate,emi,outstanding,started}
    settings: { theme:'dark', baseCur:'USD', rates:{}, household:'My Household', remind:true, leadDays:30, idleMin:15 },
    secLog: []
  };
}

/* ---------- storage ---------- */
const LS_USERS = 'budgetelle.users';
const LS_DATA = e => `budgetelle.vault.${e}`;
function getUsers() { try { return JSON.parse(localStorage.getItem(LS_USERS)) || {}; } catch { return {}; } }

/* ---------- auth ---------- */
async function signUp() {
  const em = document.getElementById('login-email').value.trim().toLowerCase();
  const pw = document.getElementById('login-pass').value;
  if (!em || pw.length < 6) return toast('Enter email and a password of 6+ characters');
  const users = getUsers();
  if (users[em]) return toast('Vault already exists — sign in instead.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await sha256hex(em + ':' + pw + ':' + btoa(String.fromCharCode(...salt)));
  users[em] = { salt: btoa(String.fromCharCode(...salt)), hash };
  localStorage.setItem(LS_USERS, JSON.stringify(users));
  await openSession(em, pw);
}
document.getElementById('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const em = document.getElementById('login-email').value.trim().toLowerCase();
  const pw = document.getElementById('login-pass').value;
  const u = getUsers()[em];
  if (!u) return showLoginErr(true);
  const hash = await sha256hex(em + ':' + pw + ':' + atob(u.salt).split('').map(c=>c.charCodeAt(0)).join(''));
  if (hash !== u.hash) return showLoginErr(true);
  await openSession(em, pw);
});
function showLoginErr(v){ document.getElementById('login-err').style.display = v ? 'block' : 'none'; }

async function openSession(email, pass) {
  const salt = Uint8Array.from(atob(getUsers()[email].salt), c => c.charCodeAt(0));
  SESSION.key = await deriveKey(pass, salt);
  SESSION.email = email;
  const raw = localStorage.getItem(LS_DATA(email));
  DB = raw ? await decryptJSON(SESSION.key, JSON.parse(raw)) : blankDB();
  resetIdle();
  enterApp();
}

/* demo data for first-run so the app isn't empty */
function seedDemo(db) {
  db.profile.name = 'Chris';
  const now = new Date();
  const mk = (off, type, cat, amt, notes) => ({
    id: uid(), date: isoOf(new Date(now.getFullYear(), now.getMonth(), Math.max(1, now.getDate() - off))),
    type, category: cat, amount: amt, cur: 'USD', notes
  });
  db.entries = [
    mk(2,'income','Salary',4200,'Monthly salary'),
    mk(5,'income','Freelance',600,'Side project'),
    mk(1,'expense','Groceries',142.50,'Weekly groceries'),
    mk(3,'expense','Dining',64.20,'Dinner out'),
    mk(4,'expense','Fuel',55.00,'Petrol'),
    mk(6,'expense','Utilities',120.35,'Electricity + internet'),
    mk(8,'expense','Online',89.99,'Amazon order'),
    mk(-25,'income','Salary',4200,'Monthly salary'),
    mk(-24,'expense','Rent',1450,'Apartment rent'),
    mk(-22,'expense','Groceries',158.10,'Weekly groceries'),
    mk(-20,'expense','Entertainment',45.00,'Cinema'),
  ];
  const ym = ymOf(now), lastM = ymOf(new Date(now.getFullYear(), now.getMonth()-1, 1));
  db.budgets = [
    { id:uid(), month:ym, category:'Groceries', limit:600 },
    { id:uid(), month:ym, category:'Dining', limit:200 },
    { id:uid(), month:ym, category:'Fuel', limit:180 },
  ];
  db.recurring = [
    { id:uid(), name:'Netflix', category:'Entertainment', amount:15.49, freq:'monthly', next:isoOf(new Date(now.getFullYear(),now.getMonth(),25)), status:'Active' },
    { id:uid(), name:'Gym membership', category:'Health', amount:45, freq:'monthly', next:isoOf(new Date(now.getFullYear(),now.getMonth()+1,3)), status:'Active' },
    { id:uid(), name:'iCloud storage', category:'Software', amount:2.99, freq:'monthly', next:isoOf(new Date(now.getFullYear(),now.getMonth()+1,9)), status:'Active' },
  ];
  for (let i=5;i>=0;i--) {
    const m = new Date(now.getFullYear(), now.getMonth()-i, 1);
    const inc = 4200+Math.random()*400, exp = 1900+Math.random()*500;
    db.entries.push(mk(-i*28-3,'income','Salary',Math.round(inc),'Monthly salary'));
    db.entries.push(mk(-i*28-5,'expense','Rent',Math.round(exp*0.6),'Apartment rent'));
    if (i>0) db.snapshots.push({ id:uid(), month:ymOf(m), assets:Math.round(52000+i*900), liabilities:185000-i*2200, notes:'Monthly snapshot' });
  }
  db.snapshots.sort((a,b)=>a.month.localeCompare(b.month));
  db.goals = [
    { id:uid(), name:'Emergency fund (6 months)', target:25000, saved:8750, byDate:isoOf(new Date(now.getFullYear()+1,8,30)), monthly:800 },
    { id:uid(), name:'Paris holiday', target:4500, saved:1600, byDate:isoOf(new Date(now.getFullYear(),11,31)), monthly:350 },
  ];
  db.assets = [
    { id:uid(), name:'Car — Toyota Corolla 2022', category:'Vehicle', value:16500, notes:'' },
    { id:uid(), name:'Index ETF portfolio', category:'Investment', value:12400, notes:'VT' },
    { id:uid(), name:'Emergency savings', category:'Bank', value:8750, notes:'High-yield' },
  ];
  db.insurance = [{ id:uid(), policy:'Car comprehensive', type:'Motor', premium:680, frequency:'yearly', due:isoOf(new Date(now.getFullYear(),now.getMonth(),now.getDate()+6)) }];
  db.documents = [{ id:uid(), doc:'Passport', type:'Passport', number:'P•••5678', holder:'Self', issued:'2021-03-05', expiry:isoOf(new Date(now.getFullYear()+2,5,20)) }];
  db.cards = [
    { id:uid(), name:'Cashback Card', bank:'Bank A', rules:[{cat:'Groceries',pct:5},{cat:'Fuel',pct:3},{cat:'Everything else',pct:1}] },
    { id:uid(), name:'Travel Rewards', bank:'Bank B', rules:[{cat:'Travel',pct:7},{cat:'Dining',pct:1}] },
  ];
  db.loans = [];
  logSec(db,'Vault created');
  return db;
}
function uid(){ return Math.random().toString(36).slice(2,10); }
function isoOf(d){ return d.toISOString().slice(0,10); }
function ymOf(d){ return d.toISOString().slice(0,7); }
function logSec(db,msg){ db.secLog.unshift({ t:new Date().toISOString(), msg }); db.secLog=db.secLog.slice(0,50); }
function logSecNow(msg){ if(DB){logSec(DB,msg); persist();} }

/* ---------- persistence ---------- */
let saveT=null;
function persist(){
  if(!SESSION.key||!DB) return;
  clearTimeout(saveT);
  saveT = setTimeout(async ()=>{
    const blob = await encryptJSON(SESSION.key, DB);
    localStorage.setItem(LS_DATA(SESSION.email), JSON.stringify(blob));
  }, 250);
}
window.addEventListener('beforeunload', ()=>{ /* best effort */ });

/* idle lock */
function resetIdle(){
  clearTimeout(SESSION.timer);
  const mins = (DB?.settings.idleMin)||15;
  SESSION.timer = setTimeout(lockVault, mins*60*1000);
}
['click','keydown','mousemove'].forEach(ev=>document.addEventListener(ev,()=>{if(SESSION.key)resetIdle();},{passive:true}));
function lockVault(){
  clearTimeout(SESSION.timer);
  SESSION.key=null; SESSION.email=null; DB=null;
  document.getElementById('app').style.display='none';
  document.getElementById('login-screen').style.display='flex';
  toast('🔒 Vault locked.');
}
function destroyVault(){
  if(!confirm('Permanently erase ALL Budgetelle data on this device? This cannot be undone.'))return;
  localStorage.removeItem(LS_DATA(SESSION.email));
  const u=getUsers(); delete u[SESSION.email];
  localStorage.setItem(LS_USERS,JSON.stringify(u));
  lockVault(); toast('Vault erased.');
}
function clearAllData(){
  if(!confirm('Clear ALL records (entries, budgets, goals, assets, etc.)?\nYour login and settings are kept. This cannot be undone.'))return;
  const keep=DB.settings, prof=DB.profile, ult=DB.ultimateGoal, logs=[];
  DB=blankDB();
  DB.settings=keep; DB.profile=prof; DB.ultimateGoal=ult;
  logSec(DB,'All data cleared');
  persist(); refreshAll();
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-dashboard').classList.add('active');
  document.querySelectorAll('.nav-item').forEach(x=>x.classList.toggle('active',x.dataset.page==='dashboard'));
  toast('All data cleared — fresh start ✓');
}

/* ---------- formatting / currency ---------- */
function fmt(amount, cur){
  cur = cur || DB.settings.baseCur;
  const sym = CURRENCIES[cur]?.s ?? cur+' ';
  return sym + Number(amount||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
}
function toBase(amount, cur){
  if(cur===DB.settings.baseCur || !cur) return amount;
  const r = DB.settings.rates[cur];
  return r ? amount*r : amount;
}

/* ---------- app shell ---------- */
function enterApp(){
  document.getElementById('login-screen').style.display='none';
  document.getElementById('app').style.display='block';
  applyTheme(DB.settings.theme==='light');
  refreshAll();
}
function applyTheme(light){
  document.documentElement.setAttribute('data-theme', light?'light':'dark');
  document.getElementById('theme-toggle').textContent = light?'☀️':'🌙';
  const sw=document.getElementById('theme-switch'); if(sw)sw.checked=light;
  DB.settings.theme = light?'light':'dark'; persist();
}
function toggleTheme(light){ applyTheme(light); logSecNow('Theme changed to '+DB.settings.theme); }
document.getElementById('theme-toggle').onclick=()=>applyTheme(document.documentElement.getAttribute('data-theme')!=='light');

document.querySelectorAll('.nav-item').forEach(n=>n.onclick=()=>{
  document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));
  n.classList.add('active');
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+n.dataset.page).classList.add('active');
});

/* modal */
function openModal(html){
  document.getElementById('modal').innerHTML=html;
  document.getElementById('modal-back').classList.add('open');
}
function closeModal(){ document.getElementById('modal-back').classList.remove('open'); }
document.getElementById('modal-back').addEventListener('click',e=>{if(e.target.id==='modal-back')closeModal();});
function toast(msg){
  const t=document.getElementById('toast'); t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2600);
}
const f=(label,input)=>`<div class="field"><label>${label}</label>${input}</div>`;
function curOptions(sel){ return Object.keys(CURRENCIES).map(c=>`<option value="${c}" ${c===(sel||DB.settings.baseCur)?'selected':''}>${c}</option>`).join(''); }
function catOptions(list,sel){ return list.map(c=>`<option ${c===sel?'selected':''}>${c}</option>`).join(''); }

/* ---------- generic entry forms (income/expense) ---------- */
function openEntry(type){
  const cats = type==='income'?CATS_INC:CATS_EXP;
  openModal(`<h3>${type==='income'?'Add income':'Add expense'}</h3>
  <form onsubmit="saveEntry(event,'${type}')">
    ${f('Date','<input type="date" id="e-date" required value="'+isoOf(new Date())+'">')}
    <div class="grid2">
      ${f('Category','<select id="e-cat">'+catOptions(cats)+'</select>')}
      ${f('Currency','<select id="e-cur">'+curOptions()+'</select>')}
    </div>
    ${f('Amount','<input type="number" step="0.01" min="0" id="e-amt" required placeholder="0.00">')}
    ${f('Notes','<input id="e-notes" placeholder="Optional note">')}
    <label style="display:flex;gap:10px;align-items:center;font-size:13px;margin-top:6px"><input type="checkbox" id="e-recur" style="width:auto"> Repeat monthly (auto-suggest in Recurring)</label>
    <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div>
  </form>`);
}
function saveEntry(e,type){
  e.preventDefault();
  const recur=document.getElementById('e-recur').checked;
  DB.entries.push({
    id:uid(), date:document.getElementById('e-date').value,
    type, category:document.getElementById('e-cat').value,
    amount:+document.getElementById('e-amt').value,
    cur:document.getElementById('e-cur').value,
    notes:document.getElementById('e-notes').value,
    recurring:recur
  });
  persist(); closeModal(); refreshAll();
  toast(type==='income'?'Income added ✓':'Expense added ✓');
}

/* ---------- dashboard ---------- */
function thisMonthEntries(){ const ym=ymOf(new Date()); return DB.entries.filter(e=>e.date.startsWith(ym)); }
function sumInBase(list,type){ return list.filter(e=>e.type===type).reduce((a,e)=>a+toBase(e.amount,e.cur),0); }
function lastNMonths(n){ const arr=[]; const d=new Date(); for(let i=n-1;i>=0;i--){arr.push(new Date(d.getFullYear(),d.getMonth()-i,1));} return arr; }

function refreshAll(){
  autoPostDue();
  renderDashboard(); renderIncome(); renderExpenses(); renderBudget(); renderRecurring();
  renderNetWorth(); renderGoals(); renderAssets(); renderInsurance(); renderDocuments();
  renderCards(); renderLoans(); renderProfile(); renderSettings(); renderSecurity();
  document.getElementById('cur-badge').textContent=(CURRENCIES[DB.settings.baseCur]?.s??'')+' '+DB.settings.baseCur;
}

function renderDashboard(){
  const tm=thisMonthEntries();
  const inc=sumInBase(tm,'income'), exp=sumInBase(tm,'expense'), net=inc-exp;
  const rate=inc>0?((net/inc)*100):0;
  const nw=DB.snapshots.length?DB.snapshots[DB.snapshots.length-1]:null;
  const nwv=nw?(nw.assets-nw.liabilities):null;
  const subTotal=tm.filter(e=>e.type==='expense'&&e.subId).reduce((a,e)=>a+toBase(e.amount,e.cur),0);
  document.getElementById('dash-kpis').innerHTML=[
    kpi('Income',fmt(inc),'pos'),kpi('Expenses',fmt(exp),'neg'),
    kpi('Net savings',fmt(net),net>=0?'pos':'neg'),
    kpi('Savings rate',rate.toFixed(1)+'%','', rate>=20?'On track':undefined),
    kpi('Subscriptions',exp>0?Math.round(subTotal/exp*100)+'% of expenses':fmt(subTotal),'bluetxt', subTotal>0?fmt(subTotal)+' this month':undefined),
    kpi('Net worth',nwv!=null?fmt(nwv):'—','goldtxt', nw?('Assets '+fmt(nw.assets)+' − Liab '+fmt(nw.liabilities)):undefined)
  ].join('');
  // cashflow bars
  const months=lastNMonths(6);
  const data=months.map(m=>{
    const ym=ymOf(m), es=DB.entries.filter(e=>e.date.startsWith(ym));
    return {lbl:m.toLocaleString('en',{month:'short'}), inc:sumInBase(es,'income'), exp:sumInBase(es,'expense')};
  });
  const max=Math.max(...data.map(d=>Math.max(d.inc,d.exp)),1);
  document.getElementById('chart-cashflow').innerHTML=data.map(d=>`
    <div class="bar-col"><div class="bars" title="${d.lbl}: ${fmt(d.inc)} in / ${fmt(d.exp)} out">
      <div style="height:${(d.inc/max)*100}%;background:var(--green)"></div>
      <div style="height:${(d.exp/max)*100}%;background:var(--red)"></div>
    </div><span class="bar-lbl">${d.lbl}</span></div>`).join('');
  // spend donut
  const byCat={}; tm.filter(e=>e.type==='expense').forEach(e=>{byCat[e.category]=(byCat[e.category]||0)+toBase(e.amount,e.cur)});
  renderDonut(document.getElementById('chart-spend'),byCat);
  // recent
  const recent=[...DB.entries].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,7);
  document.getElementById('dash-recent').innerHTML=recent.length?table(['Date','Type','Category','Amount'],
    recent.map(e=>[e.date,`<span class="pill ${e.type}">${e.type}</span>`,e.category,
    `<span class="${e.type==='income'?'pos':'neg'}">${e.type==='income'?'+':'−'}${fmt(e.amount,e.cur)}</span>`])):'<div class="empty">No activity yet.</div>';
  // renewals
  const items=[
    ...DB.insurance.map(i=>({name:i.policy,due:i.due})),
    ...DB.documents.map(d=>({name:d.doc,due:d.expiry})),
    ...DB.recurring.map(r=>({name:r.name,due:r.next}))
  ].filter(i=>i.due).sort((a,b)=>a.due.localeCompare(b.due)).slice(0,5);
  document.getElementById('dash-renewals').innerHTML=items.length?items.map(i=>{
    const days=Math.ceil((new Date(i.due)-new Date())/86400000);
    const st=days<0?['overdue','pill overdue']:days<=DB.settings.leadDays?['due soon','pill duesoon']:['current','pill current'];
    return `<div class="set-row"><div class="t">${i.name}</div><div><span class="${st[1]}">${st[0]}</span> &nbsp;<span style="color:var(--muted);font-size:13px">${days<0?Math.abs(days)+'d ago':days+'d left'} · ${i.due}</span></div></div>`;
  }).join(''):'<div class="empty">Nothing upcoming.</div>';
}
function kpi(lbl,val,color,note){return `<div class="kpi"><div class="lbl">${lbl}</div><div class="val ${color||''}">${val}</div>${note?`<div class="note">${note}</div>`:''}</div>`;}
function table(heads,rows){return `<table><thead><tr>${heads.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;}

function renderDonut(el,byCat,totalLabel){
  const keys=Object.keys(byCat); const total=Object.values(byCat).reduce((a,b)=>a+b,0);
  if(!total){el.innerHTML='<div class="empty">No spending recorded.</div>';return;}
  const colors=['#2563eb','#10b981','#d4af37','#ef4444','#8b5cf6','#f97316','#06b6d4','#84cc16','#ec4899','#14b8a6'];
  let a0=-90;
  const segs=keys.map((k,i)=>{
    const frac=byCat[k]/total, a1=a0+frac*360;
    const large=frac>0.5?1:0, r=52,cx=70,cy=70;
    const x1=cx+r*Math.cos(a0*Math.PI/180),y1=cy+r*Math.sin(a0*Math.PI/180);
    const x2=cx+r*Math.cos(a1*Math.PI/180),y2=cy+r*Math.sin(a1*Math.PI/180);
    a0=a1;
    return `<path d="M${cx},${cy} L${x1.toFixed(2)},${y1.toFixed(2)} A${r},${r} 0 ${large} 1 ${x2.toFixed(2)},${y2.toFixed(2)} Z" fill="${colors[i%colors.length]}"/>`;
  }).join('');
  el.innerHTML=`<svg width="140" height="140" viewBox="0 0 140 140">${segs}<circle cx="70" cy="70" r="34" fill="var(--card)"/><text x="70" y="66" text-anchor="middle" font-size="10" fill="var(--muted)">Total</text><text x="70" y="80" text-anchor="middle" font-size="11" font-weight="700" fill="var(--text)">${fmt(total)}</text></svg>
  <div>${keys.map((k,i)=>`<div style="font-size:13px;margin:5px 0"><i style="display:inline-block;width:11px;height:11px;border-radius:3px;background:${colors[i%colors.length]};margin-right:8px"></i>${k} — <b>${fmt(byCat[k])}</b> <span style="color:var(--muted)">(${Math.round(byCat[k]/total*100)}%)</span></div>`).join('')}</div>`;
}

/* ---------- income & expenses ---------- */
function renderIncome(){
  const tm=thisMonthEntries().filter(e=>e.type==='income');
  const total=sumInBase(tm,'income');
  document.getElementById('income-kpis').innerHTML=kpi('This month',fmt(total),'pos')+kpi('Entries',tm.length)+kpi('Top source',topSrc(tm));
  document.getElementById('income-list').innerHTML=renderEntryTable(tm,'income');
}
function renderExpenses(){
  const tm=thisMonthEntries().filter(e=>e.type==='expense');
  const total=sumInBase(tm,'expense');
  document.getElementById('expense-kpis').innerHTML=kpi('This month',fmt(total),'neg')+kpi('Entries',tm.length)+kpi('Biggest',biggest(tm));
  document.getElementById('expense-list').innerHTML=renderEntryTable(tm,'expense');
}
function topSrc(l){const c={};l.forEach(e=>c[e.category]=(c[e.category]||0)+e.amount);const t=Object.entries(c).sort((a,b)=>b[1]-a[1])[0];return t?t[0]:'—';}
function biggest(l){if(!l.length)return '—';const b=l.reduce((x,y)=>x.amount>y.amount?x:y);return fmt(b.amount,b.cur);}
function renderEntryTable(list,type){
  if(!list.length)return '<div class="empty">Nothing yet — add your first entry above.</div>';
  const sorted=[...list].sort((a,b)=>b.date.localeCompare(a.date));
  return table(['Date','Category','Amount','Notes',''],sorted.map(e=>[
    e.date, e.category,
    `<span class="${type==='income'?'pos':'neg'}">${type==='income'?'+':'−'}${fmt(e.amount,e.cur)}</span>`,
    e.notes||'—',
    `<span class="tbl-actions"><button onclick="editEntry('${e.id}')">Edit</button><button class="del" onclick="delItem('entries','${e.id}')">Delete</button></span>`
  ]));
}
function editEntry(id){
  const e=DB.entries.find(x=>x.id===id); if(!e)return;
  const cats=e.type==='income'?CATS_INC:CATS_EXP;
  openModal(`<h3>Edit ${e.type}</h3><form onsubmit="updateEntry(event,'${id}')">
    ${f('Date',`<input type="date" id="e-date" value="${e.date}" required>`)}
    <div class="grid2">${f('Category',`<select id="e-cat">${catOptions(cats,e.category)}</select>`)}${f('Currency',`<select id="e-cur">${curOptions(e.cur)}</select>`)}</div>
    ${f('Amount',`<input type="number" step="0.01" id="e-amt" value="${e.amount}" required>`)}
    ${f('Notes',`<input id="e-notes" value="${escAttr(e.notes||'')}">`)}
    <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);
}
function updateEntry(e,id){
  e.preventDefault();
  const x=DB.entries.find(x=>x.id===id);
  x.date=v('e-date');x.category=v('e-cat');x.cur=v('e-cur');x.amount=+v('e-amt');x.notes=v('e-notes');
  persist();closeModal();refreshAll();toast('Updated ✓');
}
function v(id){return document.getElementById(id).value;}

/* ---------- budget ---------- */
function renderBudget(){
  const ym=ymOf(new Date());
  document.getElementById('budget-month-lbl').textContent=new Date().toLocaleString('en',{month:'long',year:'numeric'});
  const bs=DB.budgets.filter(b=>b.month===ym);
  const tm=thisMonthEntries().filter(e=>e.type==='expense');
  const spentBy={};tm.forEach(e=>spentBy[e.category]=(spentBy[e.category]||0)+toBase(e.amount,e.cur));
  const totB=bs.reduce((a,b)=>a+b.limit,0);
  const totS=bs.reduce((a,b)=>a+(spentBy[b.category]||0),0);
  document.getElementById('budget-kpis').innerHTML=
    kpi('Total budgeted',fmt(totB))+kpi('Spent (tracked cats)',fmt(totS),totS>totB?'neg':'pos')+kpi('Remaining',fmt(totB-totS),totB-totS>=0?'pos':'neg');
  document.getElementById('budget-list').innerHTML=bs.length?bs.map(b=>{
    const sp=spentBy[b.category]||0,pc=Math.min(100,sp/b.limit*100),over=sp>b.limit;
    return `<div style="margin-bottom:18px"><div class="bar-row"><b>${b.category}</b><span>${fmt(sp)} of ${fmt(b.limit)} ${over?'<span class="pill expense">over</span>':''}</span></div>
    <div class="progress"><div style="width:${pc}%;background:${over?'var(--red)':'linear-gradient(90deg,var(--blue),var(--green))'}"></div></div></div>
    <span class="tbl-actions"><button onclick="editBudget('${b.id}')">Edit</button><button class="del" onclick="delItem('budgets','${b.id}')">Delete</button></span>`;
  }).join(''):'<div class="empty">No budgets set for this month.</div>';
}
function openBudget(){
  openModal(`<h3>Add budget</h3><form onsubmit="saveBudget(event)">
    ${f('Category',`<select id="b-cat">${catOptions(CATS_EXP)}</select>`)}
    ${f('Monthly limit','<input type="number" step="0.01" id="b-limit" required>')}
    <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);
}
function saveBudget(e){e.preventDefault();DB.budgets.push({id:uid(),month:ymOf(new Date()),category:v('b-cat'),limit:+v('b-limit')});persist();closeModal();refreshAll();toast('Budget added ✓');}
function editBudget(id){const b=DB.budgets.find(x=>x.id===id);
  openModal(`<h3>Edit budget</h3><form onsubmit="updBudget(event,'${id}')">
  ${f('Limit',`<input type="number" step="0.01" id="b-limit" value="${b.limit}" required>`)}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updBudget(e,id){e.preventDefault();DB.budgets.find(x=>x.id===id).limit=+v('b-limit');persist();closeModal();refreshAll();}

/* ---------- recurring ---------- */
function monthlyEquiv(r){const a=r.amount;return r.freq==='yearly'?a/12:r.freq==='quarterly'?a/3:a;}
function renderRecurring(){
  const act=DB.recurring.filter(r=>r.status==='Active');
  document.getElementById('recur-kpis').innerHTML=
    kpi('Monthly equivalent',fmt(act.reduce((a,r)=>a+monthlyEquiv(r),0)))+kpi('Active items',act.length)
    +kpi('Posted this month',postedCount());
  const sorted=[...DB.recurring].sort((a,b)=>(a.next||'').localeCompare(b.next||''));
  document.getElementById('recurring-list').innerHTML=DB.recurring.length?table(['Name','Category','Amount','Frequency','Next','Status',''],
    sorted.map(r=>{
      const due=r.status==='Active'&&r.next&&r.next<=isoOf(new Date());
      return [r.name,r.category,fmt(r.amount),r.freq,r.next,
      `<span class="pill ${r.status.toLowerCase()}">${r.status}</span>${due?' <span class="pill duesoon">due</span>':''}`,
      `${due?`<button class="link-btn" onclick="postRecurring('${r.id}')">Post to Expenses</button> `:''}<span class="tbl-actions"><button onclick="editRecurring('${r.id}')">Edit</button><button class="del" onclick="delItem('recurring','${r.id}')">Delete</button></span>`]}))
    :'<div class="empty">No subscriptions yet.</div>';
}
function postedCount(){
  const ym=ymOf(new Date());
  return DB.entries.filter(e=>e.type==='expense'&&e.subId&&e.date.startsWith(ym)).length;
}
function postRecurring(id){
  const r=DB.recurring.find(x=>x.id===id); if(!r)return;
  DB.entries.push({id:uid(),date:r.next,type:'expense',category:r.category,amount:r.amount,cur:DB.settings.baseCur,notes:r.name+' (subscription)',subId:r.id});
  // advance the next-due date by one period
  const d=new Date(r.next);
  if(r.freq==='monthly')d.setMonth(d.getMonth()+1);
  else if(r.freq==='quarterly')d.setMonth(d.getMonth()+3);
  else d.setFullYear(d.getFullYear()+1);
  r.next=isoOf(d);
  persist();refreshAll();toast(`${r.name} posted to Expenses ✓ (next: ${r.next})`);
}
function autoPostDue(){
  const today=isoOf(new Date());
  DB.recurring.filter(r=>r.status==='Active'&&r.next&&r.next<=today).forEach(r=>postRecurring(r.id));
}
function openRecurring(){
  openModal(`<h3>Add recurring</h3><form onsubmit="saveRecurring(event)">
    ${f('Name','<input id="r-name" required>')}
    <div class="grid2">${f('Category',`<select id="r-cat">${catOptions(CATS_EXP)}</select>`)}${f('Amount','<input type="number" step="0.01" id="r-amt" required>')}</div>
    <div class="grid2">${f('Frequency',`<select id="r-freq"><option>monthly</option><option>quarterly</option><option>yearly</option></select>`)}${f('Next due','<input type="date" id="r-next" required>')}</div>
    <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);
}
function saveRecurring(e){e.preventDefault();DB.recurring.push({id:uid(),name:v('r-name'),category:v('r-cat'),amount:+v('r-amt'),freq:v('r-freq'),next:v('r-next'),status:'Active'});persist();closeModal();refreshAll();toast('Added ✓');}
function editRecurring(id){const r=DB.recurring.find(x=>x.id===id);
  openModal(`<h3>Edit recurring</h3><form onsubmit="updRecurring(event,'${id}')">
  <div class="grid2">${f('Amount',`<input type="number" step="0.01" id="r-amt" value="${r.amount}" required>`)}${f('Status',`<select id="r-st"><option ${r.status==='Active'?'selected':''}>Active</option><option ${r.status==='Cancelled'?'selected':''}>Cancelled</option></select>`)}</div>
  ${f('Next due',`<input type="date" id="r-next" value="${r.next}" required>`)}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updRecurring(e,id){e.preventDefault();const r=DB.recurring.find(x=>x.id===id);r.amount=+v('r-amt');r.status=v('r-st');r.next=v('r-next');persist();closeModal();refreshAll();}

/* ---------- net worth ---------- */
function renderNetWorth(){
  const s=DB.snapshots;const latest=s[s.length-1];
  document.getElementById('nw-kpis').innerHTML=
    kpi('Latest assets',latest?fmt(latest.assets):'—','pos')+kpi('Latest liabilities',latest?fmt(latest.liabilities):'—','neg')
    +kpi('Net worth',latest?fmt(latest.assets-latest.liabilities):'—','goldtxt');
  // svg line chart
  const svg=document.getElementById('nw-chart');
  if(s.length<2){svg.innerHTML='';}
  else{
    const W=800,H=200,P=30;
    const vals=s.map(x=>x.assets-x.liabilities);
    const mn=Math.min(...vals)*0.98,mx=Math.max(...vals)*1.02;
    const X=i=>P+(W-2*P)*(i/(s.length-1)),Y=v=>H-P-(H-2*P)*((v-mn)/(mx-mn||1));
    const pts=vals.map((v,i)=>`${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
    svg.innerHTML=`<polyline points="${pts}" fill="none" stroke="#d4af37" stroke-width="3"/>
      ${vals.map((v,i)=>`<circle cx="${X(i)}" cy="${Y(v)}" r="4" fill="#2563eb"/>`).join('')}
      <line x1="${P}" y1="${H-P}" x2="${W-P}" y2="${H-P}" stroke="var(--border)"/>`;
  }
  document.getElementById('nw-table').innerHTML=s.length?table(['Month','Assets','Liabilities','Net','Notes',''],
    [...s].reverse().map(x=>[x.month,`<span class="pos">${fmt(x.assets)}</span>`,`<span class="neg">${fmt(x.liabilities)}</span>`,`<b class="goldtxt">${fmt(x.assets-x.liabilities)}</b>`,x.notes||'—',
    `<span class="tbl-actions"><button onclick="delItem('snapshots','${x.id}')">Delete</button></span>`]))
    :'<div class="empty">No snapshots yet.</div>';
}
function openSnapshot(){
  openModal(`<h3>Add snapshot</h3><form onsubmit="saveSnap(event)">
    ${f('Month','<input type="month" id="s-month" required value="'+ymOf(new Date())+'">')}
    <div class="grid2">${f('Total assets','<input type="number" step="0.01" id="s-a" required>')}${f('Total liabilities','<input type="number" step="0.01" id="s-l" required>')}</div>
    ${f('Notes','<input id="s-notes" placeholder="Monthly snapshot">')}
    <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);
}
function saveSnap(e){e.preventDefault();DB.snapshots=DB.snapshots.filter(s=>s.month!==v('s-month'));
  DB.snapshots.push({id:uid(),month:v('s-month'),assets:+v('s-a'),liabilities:+v('s-l'),notes:v('s-notes')});
  DB.snapshots.sort((a,b)=>a.month.localeCompare(b.month));persist();closeModal();refreshAll();toast('Snapshot saved ✓');}

/* ---------- goals ---------- */
function renderGoals(){
  const el=document.getElementById('goals-list');
  el.innerHTML=DB.goals.length?DB.goals.map(g=>{
    const pc=Math.min(100,g.saved/g.target*100);
    const monthsLeft=Math.max(0,(g.target-g.saved)/(g.monthly||1));
    return `<div class="card"><div style="display:flex;justify-content:space-between"><h3>${g.name}</h3>
      <span class="tbl-actions"><button onclick="editGoal('${g.id}')">Edit</button><button class="del" onclick="delItem('goals','${g.id}')">Delete</button></span></div>
      <div style="font-size:22px;font-weight:700">${fmt(g.saved)} <span style="color:var(--muted);font-size:14px">of ${fmt(g.target)}</span></div>
      <div class="progress"><div style="width:${pc}%"></div></div>
      <div class="bar-row"><span class="bluetxt">${Math.round(pc)}% funded</span><span style="color:var(--muted)">by ${g.byDate}</span></div>
      <div class="note" style="color:var(--muted);font-size:13px;margin-top:8px">${fmt(g.monthly)}/mo → about ${monthsLeft.toFixed(1)} months to go</div></div>`;
  }).join(''):'<div class="card empty">No goals yet — set your first one!</div>';
}
function openGoal(){
  openModal(`<h3>Add goal</h3><form onsubmit="saveGoal(event)">
    ${f('Goal name','<input id="g-name" required placeholder="e.g. Japan holiday">')}
    <div class="grid2">${f('Target amount','<input type="number" step="0.01" id="g-target" required>')}${f('Already saved','<input type="number" step="0.01" id="g-saved" value="0">')}</div>
    <div class="grid2">${f('Target date','<input type="date" id="g-by" required>')}${f('Monthly contribution','<input type="number" step="0.01" id="g-monthly" required>')}</div>
    <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);
}
function saveGoal(e){e.preventDefault();DB.goals.push({id:uid(),name:v('g-name'),target:+v('g-target'),saved:+v('g-saved'),byDate:v('g-by'),monthly:+v('g-monthly')});persist();closeModal();refreshAll();toast('Goal set 🏁');}
function editGoal(id){const g=DB.goals.find(x=>x.id===id);
  openModal(`<h3>Edit goal</h3><form onsubmit="updGoal(event,'${id}')">
  ${f('Saved so far',`<input type="number" step="0.01" id="g-saved" value="${g.saved}" required>`)}
  <div class="grid2">${f('Target',`<input type="number" step="0.01" id="g-target" value="${g.target}" required>`)}${f('Monthly',`<input type="number" step="0.01" id="g-monthly" value="${g.monthly}" required>`)}</div>
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updGoal(e,id){e.preventDefault();const g=DB.goals.find(x=>x.id===id);g.saved=+v('g-saved');g.target=+v('g-target');g.monthly=+v('g-monthly');persist();closeModal();refreshAll();}

/* ---------- assets ---------- */
function renderAssets(){
  const byCat={};DB.assets.forEach(a=>byCat[a.category]=(byCat[a.category]||0)+a.value);
  const tot=Object.values(byCat).reduce((a,b)=>a+b,0);
  document.getElementById('asset-kpis').innerHTML=kpi('Total value',fmt(tot),'goldtxt')
    +Object.entries(byCat).slice(0,3).map(([c,v])=>kpi(c,fmt(v))).join('');
  document.getElementById('asset-table').innerHTML=DB.assets.length?table(['Name','Category','Value','Notes',''],
    DB.assets.map(a=>[a.name,a.category,`<b>${fmt(a.value)}</b>`,a.notes||'—',
    `<span class="tbl-actions"><button onclick="editAssetSimple('${a.id}')">Edit</button><button class="del" onclick="delItem('assets','${a.id}')">Delete</button></span>`]))
    :'<div class="empty">Nothing recorded yet — add what you own above.</div>';
}
function rollupNetWorth(){
  const assets=DB.assets.reduce((s,a)=>s+a.value,0);
  const liab=DB.loans.reduce((s,l)=>s+l.outstanding,0);
  if(!assets&&!liab)return toast('Add items in What I Own and loans first.');
  const ym=ymOf(new Date());
  DB.snapshots=DB.snapshots.filter(s=>s.month!==ym);
  DB.snapshots.push({id:uid(),month:ym,assets,liabilities:liab,notes:'Rolled up from What I Own'});
  DB.snapshots.sort((a,b)=>a.month.localeCompare(b.month));
  persist();refreshAll();toast(`Net Worth snapshot for ${ym} saved ✓`);
}
function openAsset(){openModal(`<h3>Add asset</h3><form onsubmit="saveAsset(event)">
  ${f('Name','<input id="a-name" required>')}
  <div class="grid2">${f('Category',`<select id="a-cat"><option>Property</option><option>Vehicle</option><option>Investment</option><option>Bank</option><option>Gold</option><option>Other</option></select>`)}${f('Value','<input type="number" step="0.01" id="a-val" required>')}</div>
  ${f('Notes','<input id="a-notes">')}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function saveAsset(e){e.preventDefault();DB.assets.push({id:uid(),name:v('a-name'),category:v('a-cat'),value:+v('a-val'),notes:v('a-notes')});persist();closeModal();refreshAll();toast('Asset added ✓');}
function editAssetSimple(id){const a=DB.assets.find(x=>x.id===id);
  openModal(`<h3>Edit asset</h3><form onsubmit="updAsset(event,'${id}')">
  ${f('Value',`<input type="number" step="0.01" id="a-val" value="${a.value}" required>`)}${f('Notes',`<input id="a-notes" value="${escAttr(a.notes||'')}">`)}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updAsset(e,id){e.preventDefault();const a=DB.assets.find(x=>x.id===id);a.value=+v('a-val');a.notes=v('a-notes');persist();closeModal();refreshAll();}
function escAttr(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');}

/* ---------- insurance ---------- */
function statusFor(due){const days=Math.ceil((new Date(due)-new Date())/86400000);return days<0?['Overdue','expense']:days<=(DB.settings.leadDays)?['Due soon','duesoon']:['Current','active'];}
function renderInsurance(){
  document.getElementById('ins-table').innerHTML=DB.insurance.length?table(['Policy','Type','Premium','Frequency','Due','Status',''],
    DB.insurance.map(i=>{const st=statusFor(i.due);return [i.policy,i.type,fmt(i.premium),i.frequency,i.due,`<span class="pill ${st[1]}">${st[0]}</span>`,
    `<span class="tbl-actions"><button onclick="editPolicy('${i.id}')">Edit</button><button class="del" onclick="delItem('insurance','${i.id}')">Delete</button></span>`]}))
    :'<div class="empty">No policies.</div>';
}
function openPolicy(){openModal(`<h3>Add policy</h3><form onsubmit="savePolicy(event)">
  <div class="grid2">${f('Policy name','<input id="i-policy" required>')}${f('Type',`<select id="i-type"><option>Motor</option><option>Health</option><option>Home</option><option>Life</option><option>Travel</option><option>Other</option></select>`)}</div>
  <div class="grid2">${f('Premium','<input type="number" step="0.01" id="i-prem" required>')}${f('Frequency',`<select id="i-freq"><option>yearly</option><option>quarterly</option><option>monthly</option></select>`)}</div>
  ${f('Due date','<input type="date" id="i-due" required>')}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function savePolicy(e){e.preventDefault();DB.insurance.push({id:uid(),policy:v('i-policy'),type:v('i-type'),premium:+v('i-prem'),frequency:v('i-freq'),due:v('i-due')});persist();closeModal();refreshAll();toast('Policy added ✓');}
function editPolicy(id){const p=DB.insurance.find(x=>x.id===id);
  openModal(`<h3>Edit policy</h3><form onsubmit="updPolicy(event,'${id}')">
  <div class="grid2">${f('Premium',`<input type="number" step="0.01" id="i-prem" value="${p.premium}" required>`)}${f('Due date',`<input type="date" id="i-due" value="${p.due}" required>`)}</div>
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updPolicy(e,id){e.preventDefault();const p=DB.insurance.find(x=>x.id===id);p.premium=+v('i-prem');p.due=v('i-due');persist();closeModal();refreshAll();}

/* ---------- documents ---------- */
function renderDocuments(){
  document.getElementById('doc-table').innerHTML=DB.documents.length?table(['Document','Number','Holder','Expiry','Status',''],
    DB.documents.map(d=>{const st=statusFor(d.expiry);return [`${d.doc} <span style="color:var(--muted)">(${d.type})</span>`,d.number,d.holder,d.expiry,`<span class="pill ${st[1]}">${st[0]}</span>`,
    `<span class="tbl-actions"><button onclick="editDoc('${d.id}')">Edit</button><button class="del" onclick="delItem('documents','${d.id}')">Delete</button></span>`]}))
    :'<div class="empty">No documents stored. Numbers are masked — store only what you need.</div>';
}
function openDoc(){openModal(`<h3>Add document</h3><form onsubmit="saveDoc(event)">
  <div class="grid2">${f('Document','<input id="d-doc" required placeholder="Passport">')}${f('Type',`<select id="d-type"><option>Passport</option><option>National ID</option><option>Driving Licence</option><option>Visa</option><option>Other</option></select>`)}</div>
  <div class="grid2">${f('Number','<input id="d-num" placeholder="Use partial/masked number">')}${f('Holder','<input id="d-holder" value="Self">')}</div>
  ${f('Expiry','<input type="date" id="d-exp" required>')}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function saveDoc(e){e.preventDefault();DB.documents.push({id:uid(),doc:v('d-doc'),type:v('d-type'),number:v('d-num'),holder:v('d-holder'),expiry:v('d-exp')});persist();closeModal();refreshAll();toast('Document added ✓');}
function editDoc(id){const d=DB.documents.find(x=>x.id===id);
  openModal(`<h3>Edit document</h3><form onsubmit="updDoc(event,'${id}')">
  ${f('Expiry',`<input type="date" id="d-exp" value="${d.expiry}" required>`)}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updDoc(e,id){e.preventDefault();DB.documents.find(x=>x.id===id).expiry=v('d-exp');persist();closeModal();refreshAll();}

/* ---------- credit cards ---------- */
function renderCards(){
  document.getElementById('card-list').innerHTML=DB.cards.length?DB.cards.map(c=>`
    <div class="card" style="background:var(--card2);margin-bottom:14px">
      <div style="display:flex;justify-content:space-between"><b>${c.name}</b> <span style="color:var(--muted)">${c.bank}</span></div>
      ${c.rules.map(r=>`<div class="bar-row"><span>${r.cat}</span><b class="goldtxt">${r.pct}% back</b></div>`).join('')}
      <span class="tbl-actions mt" style="display:block"><button onclick="editCard('${c.id}')">Edit rules</button><button class="del" onclick="delItem('cards','${c.id}')">Delete</button></span>
    </div>`).join(''):'<div class="empty">No cards added.</div>';
}
function openCard(){openModal(`<h3>Add card</h3><form onsubmit="saveCard(event)">
  <div class="grid2">${f('Card name','<input id="c-name" required>')}${f('Bank','<input id="c-bank" required>')}</div>
  ${f('Best rule — category',`<select id="c-cat">${catOptions(CATS_EXP.concat(['Travel']))}</select>`)}
  ${f('Cashback % for that category','<input type="number" step="0.1" id="c-pct" required placeholder="5">')}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function saveCard(e){e.preventDefault();DB.cards.push({id:uid(),name:v('c-name'),bank:v('c-bank'),rules:[{cat:v('c-cat'),pct:+v('c-pct')}]});persist();closeModal();refreshAll();toast('Card added ✓');}
function editCard(id){const c=DB.cards.find(x=>x.id===id);
  openModal(`<h3>Reward rules — ${c.name}</h3><form onsubmit="updCard(event,'${id}')">
  ${f('Rules (format: Category:%, one per line)',`<textarea id="c-rules" rows="4">${c.rules.map(r=>r.cat+':'+r.pct).join('\n')}</textarea>`)}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updCard(e,id){e.preventDefault();const c=DB.cards.find(x=>x.id===id);
  c.rules=v('c-rules').split('\n').filter(Boolean).map(l=>{const[cat,pct]=l.split(':');return{cat:cat.trim(),pct:+pct};});
  persist();closeModal();refreshAll();}
function recommendCard(ev){
  ev.preventDefault();
  const cat=v('rec-cat').toLowerCase(),amt=+v('rec-amt');
  let best=null;
  DB.cards.forEach(c=>c.rules.forEach(r=>{if(cat.includes(r.cat.toLowerCase())||r.cat.toLowerCase().includes(cat)){
    if(!best||r.pct>best.pct)best={card:c.name,pct:r.pct};}}));
  document.getElementById('rec-result').innerHTML=best?
    `<div class="set-row"><div class="t">💡 Use <span class="goldtxt">${best.card}</span></div><div><b class="goldtxt">${best.pct}%</b> back ≈ <b>${fmt(amt*best.pct/100)}</b> on this purchase</div></div>`
    :'<div class="empty">No matching rule found. Add reward rules to your cards first.</div>';
  return false;
}

/* ---------- loans ---------- */
function renderLoans(){
  const out=DB.loans.reduce((a,l)=>a+l.outstanding,0);
  const emi=DB.loans.reduce((a,l)=>a+l.emi,0);
  document.getElementById('loan-kpis').innerHTML=kpi('Total outstanding',fmt(out),'goldtxt')+kpi('Monthly EMI',fmt(emi),'bluetxt')+kpi('Active loans',DB.loans.length);
  document.getElementById('loan-table').innerHTML=DB.loans.length?table(['Loan','Lender','Principal','Rate','EMI','Outstanding','Started',''],
    DB.loans.map(l=>[l.name,l.lender,fmt(l.principal),l.rate+'%',fmt(l.emi),`<b class="goldtxt">${fmt(l.outstanding)}</b>`,l.started,
    `<span class="tbl-actions"><button onclick="editLoan('${l.id}')">Edit</button><button class="del" onclick="delItem('loans','${l.id}')">Delete</button></span>`]))
    :'<div class="empty">Debt-free! No loans recorded. 🎉</div>';
}
function openLoan(){openModal(`<h3>Add loan</h3><form onsubmit="saveLoan(event)">
  <div class="grid2">${f('Loan name','<input id="l-name" required>')}${f('Lender','<input id="l-lender" required>')}</div>
  <div class="grid3">${f('Principal','<input type="number" step="0.01" id="l-prin" required>')}${f('Rate %','<input type="number" step="0.01" id="l-rate" required>')}${f('Monthly EMI','<input type="number" step="0.01" id="l-emi" required>')}</div>
  <div class="grid2">${f('Outstanding','<input type="number" step="0.01" id="l-out" required>')}${f('Started','<input type="date" id="l-start" required>')}</div>
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function saveLoan(e){e.preventDefault();DB.loans.push({id:uid(),name:v('l-name'),lender:v('l-lender'),principal:+v('l-prin'),rate:+v('l-rate'),emi:+v('l-emi'),outstanding:+v('l-out'),started:v('l-start')});persist();closeModal();refreshAll();toast('Loan added ✓');}
function editLoan(id){const l=DB.loans.find(x=>x.id===id);
  openModal(`<h3>Edit loan</h3><form onsubmit="updLoan(event,'${id}')">
  ${f('Outstanding balance',`<input type="number" step="0.01" id="l-out" value="${l.outstanding}" required>`)}
  ${f('Monthly EMI',`<input type="number" step="0.01" id="l-emi" value="${l.emi}" required>`)}
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function updLoan(e,id){e.preventDefault();const l=DB.loans.find(x=>x.id===id);l.outstanding=+v('l-out');l.emi=+v('l-emi');persist();closeModal();refreshAll();}

/* ---------- profile ---------- */
function renderProfile(){
  document.getElementById('prof-name').textContent=DB.profile.name||SESSION.email;
  document.getElementById('profile-table').innerHTML=[
    ['Email',SESSION.email],['Mobile',DB.profile.mobile||'Not set'],
    ['Nickname',DB.profile.nickname||'Not set'],['Household',DB.settings.household]
  ].map(r=>`<tr><th style="border:none;width:160px">${r[0]}</th><td style="border:none">${r[1]}</td></tr>`).join('');
  const g=document.getElementById('ult-goal');if(g&&document.activeElement!==g)g.value=DB.ultimateGoal||'';
}
function openEditProfile(){
  openModal(`<h3>Edit profile</h3><form onsubmit="saveProfile(event)">
  ${f('Display name',`<input id="p-name" value="${escAttr(DB.profile.name)}" required>`)}
  <div class="grid2">${f('Mobile',`<input id="p-mobile" value="${escAttr(DB.profile.mobile||'')}">`)}${f('Nickname',`<input id="p-nick" value="${escAttr(DB.profile.nickname||'')}">`)}</div>
  <div class="actions"><button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold">Save</button></div></form>`);}
function saveProfile(e){e.preventDefault();DB.profile={name:v('p-name'),mobile:v('p-mobile'),nickname:v('p-nick')};persist();closeModal();refreshAll();toast('Profile updated ✓');}
function saveUltGoal(){DB.ultimateGoal=v('ult-goal');persist();}

/* ---------- security page ---------- */
function renderSecurity(){
  const l=document.getElementById('sec-log');
  l.innerHTML=(DB.secLog||[]).slice(0,6).map(s=>`• ${s.msg} — ${new Date(s.t).toLocaleDateString()} ${new Date(s.t).toLocaleTimeString()}`).join('<br>')||'No activity yet.';
  document.getElementById('idle-min').value=DB.settings.idleMin;
}
function saveIdle(){DB.settings.idleMin=Math.max(1,+v('idle-min'));persist();resetIdle();logSecNow('Auto-lock changed to '+DB.settings.idleMin+' min');toast('Saved ✓');}

/* ---------- settings ---------- */
function renderSettings(){
  const sel=document.getElementById('base-cur');
  sel.innerHTML=curOptions(DB.settings.baseCur);
  const ec=document.getElementById('extra-curs');
  const rates=Object.entries(DB.settings.rates);
  ec.innerHTML=rates.length?rates.map(([c,r])=>`<div class="set-row"><div class="t">${CURRENCIES[c]?.s??''} ${c}</div>
    <div style="display:flex;align-items:center;gap:10px"><span style="color:var(--muted);font-size:13px">1 ${c} = ${r} ${DB.settings.baseCur}</span>
    <button class="btn btn-danger" style="padding:5px 12px;font-size:12px" onclick="removeCurrency('${c}')">Remove</button></div></div>`).join('')
    :'<div class="empty" style="padding:16px">Only the base currency is active. Add more below.</div>';
  document.getElementById('hh-name').value=DB.settings.household;
  document.getElementById('remind-on').checked=DB.settings.remind;
  document.getElementById('lead-days').value=DB.settings.leadDays;
}
function saveBaseCur(){
  const prev=DB.settings.baseCur;
  DB.settings.baseCur=v('base-cur');
  if(prev!==DB.settings.baseCur){
    // re-express existing manual rates relative to new base
    DB.settings.rates={};
    toast(`Default currency set to ${{USD:'$',EUR:'€',GBP:'£'}[DB.settings.baseCur]??''} ${DB.settings.baseCur}`);
  }
  persist();refreshAll();
}
function addCurrency(ev){
  ev.preventDefault();
  const c=v('new-cur'),r=+v('cur-rate');
  if(c===DB.settings.baseCur)return toast('That is already the base currency.');
  DB.settings.rates[c]=r;persist();renderSettings();refreshAll();toast(`${c} added @ 1 ${c} = ${r} ${DB.settings.baseCur}`);
}
function removeCurrency(c){delete DB.settings.rates[c];persist();renderSettings();refreshAll();}
function saveHousehold(){DB.settings.household=v('hh-name');persist();refreshAll();toast('Saved ✓');}
function saveRemind(){DB.settings.remind=document.getElementById('remind-on').checked;persist();}
function saveLead(){DB.settings.leadDays=Math.max(1,+v('lead-days'));persist();refreshAll();toast('Saved ✓');}

/* ---------- export / import ---------- */
function exportData(){
  const blob=new Blob([JSON.stringify(DB,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download=`budgetelle-export-${isoOf(new Date())}.json`;a.click();
  toast('Exported decrypted JSON — keep it safe!');
}
function importData(ev){
  const file=ev.target.files[0];if(!file)return;
  const rd=new FileReader();
  rd.onload=async()=>{
    try{
      const data=JSON.parse(rd.result);
      if(!data.entries||!data.settings)throw 0;
      DB=Object.assign(blankDB(),data);
      persist();refreshAll();toast('Backup restored ✓');
    }catch{toast('Invalid backup file.');}
  };
  rd.readAsText(file);
}

/* ---------- password recovery & change ---------- */
function forgotPassword(){
  const em=document.getElementById('login-email').value.trim().toLowerCase();
  openModal(`<h3>Reset your vault</h3>
  <p style="color:var(--muted);font-size:13.5px;line-height:1.65;margin-bottom:18px">Budgetelle is zero-knowledge: your data is encrypted with a key derived from your password, so <b style="color:var(--text)">no one — including us — can recover it</b>. If you've lost your password, your existing data cannot be decrypted. You can reset the vault for this email and start fresh.</p>
  ${f('Email','<input id="fp-email" type="email" value="'+escAttr(em)+'" required>')}
  ${f('New password (min 6 characters)','<input id="fp-pass" type="password" minlength="6" required>' )}
  ${f('Confirm new password','<input id="fp-pass2" type="password" minlength="6" required>')}
  <p class="err" id="fp-err"></p>
  <div class="actions"><button class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold" onclick="doReset()">Reset vault</button></div>`);
}
async function doReset(){
  const em=v('fp-email').trim().toLowerCase(),p1=v('fp-pass'),p2=v('fp-pass2');
  const errEl=document.getElementById('fp-err');
  if(p1!==p2){errEl.textContent='Passwords do not match.';errEl.style.display='block';return;}
  if(!getUsers()[em]){errEl.textContent='No vault exists for that email.';errEl.style.display='block';return;}
  // wipe old encrypted blob, register new credential
  localStorage.removeItem(LS_DATA(em));
  const users=getUsers();
  const salt=crypto.getRandomValues(new Uint8Array(16));
  users[em]={salt:btoa(String.fromCharCode(...salt)),hash:await sha256hex(em+':'+p1+':'+btoa(String.fromCharCode(...salt)))};
  localStorage.setItem(LS_USERS,JSON.stringify(users));
  closeModal();toast('Vault reset. Sign in with your new password.');
}
async function changePassword(){
  openModal(`<h3>Change password</h3>
  ${f('Current password','<input id="cp-old" type="password" required>')}
  ${f('New password (min 6)','<input id="cp-new" type="password" minlength="6" required>')}
  ${f('Confirm new password','<input id="cp-new2" type="password" minlength="6" required>')}
  <div class="actions"><button class="btn btn-ghost" onclick="closeModal()">Cancel</button><button class="btn btn-gold" onclick="doChangePass()">Update</button></div>`);
}
async function doChangePass(){
  const oldP=v('cp-old'),n1=v('cp-new'),n2=v('cp-new2');
  if(n1!==n2)return toast('New passwords do not match.');
  // verify current password by decrypting
  const u=getUsers()[SESSION.email];
  const oldSalt=Uint8Array.from(atob(u.salt),c=>c.charCodeAt(0));
  try{ await decryptJSON(await deriveKey(oldP,oldSalt), JSON.parse(localStorage.getItem(LS_DATA(SESSION.email)))); }
  catch{ return toast('Current password is incorrect.'); }
  if(oldP===n1)return toast('New password must differ from current.');
  // re-key: derive new salt+key, re-encrypt DB, update credential
  const newSalt=crypto.getRandomValues(new Uint8Array(16));
  SESSION.key=await deriveKey(n1,newSalt);
  const blob=await encryptJSON(SESSION.key,DB);
  localStorage.setItem(LS_DATA(SESSION.email),JSON.stringify(blob));
  const users=getUsers();
  users[SESSION.email]={salt:btoa(String.fromCharCode(...newSalt)),hash:await sha256hex(SESSION.email+':'+n1+':'+btoa(String.fromCharCode(...newSalt)))};
  localStorage.setItem(LS_USERS,JSON.stringify(users));
  closeModal();logSecNow('Password changed');renderSecurity();toast('Password updated ✓');
}

/* ---------- Google sign-in ---------- */
async function googleSignIn(){
  try{
    const cfg = await (await fetch('/api/auth/config')).json();
    if(cfg.enabled){ window.location.href='/api/auth/google/start'; return; }
    toast('Google sign-in is being set up — use email & password for now, or check back soon.');
  }catch{ toast('Google sign-in is unavailable right now. Use email & password.'); }
}
// After returning from Google: open a cloud-backed session for that account
async function handleGoogleReturn(){
  const p=new URLSearchParams(location.search);
  const auth=p.get('auth');
  if(!auth)return;
  history.replaceState(null,'',location.pathname);
  if(auth==='google'){
    const email=p.get('email'),name=p.get('name')||'';
    // create the vault if this Google account has never signed in before
    const users=getUsers();
    if(!users[email]){
      const salt=crypto.getRandomValues(new Uint8Array(16));
      // random high-entropy local password; the real auth lives in the HttpOnly server session
      const rp=crypto.getRandomValues(new Uint8Array(24)).reduce((s,b)=>s+b.toString(16).padStart(2,'0'),'');
      users[email]={salt:btoa(String.fromCharCode(...salt)),hash:await sha256hex(email+':'+rp+':'+btoa(String.fromCharCode(...salt)))};
      localStorage.setItem(LS_USERS,JSON.stringify(users));
      localStorage.setItem('budgetelle.gpass.'+email,rp); // lets them also unlock locally
    }
    document.getElementById('login-email').value=email;
    const pw=localStorage.getItem('budgetelle.gpass.'+email);
    document.getElementById('login-pass').value=pw;
    await openSession(email,pw);
    if(name&&!DB.profile.name){DB.profile.name=name.split(' ')[0];persist();}
    logSecNow('Signed in with Google');renderSecurity();
    toast(`Welcome${name?', '+name.split(' ')[0]:''} — signed in with Google ✓`);
  } else if(auth==='failed'){
    toast('Google sign-in didn\'t complete. Please try again or use email & password.');
  } else if(auth==='unconfigured'){
    toast('Google sign-in is being set up — use email & password for now.');
  }
}
handleGoogleReturn();

/* ---------- ADVISOR (local rules engine — no AI server, privacy-first) ---------- */
const chat=document.getElementById('chat');
function pushMsg(txt,who){
  const m=document.createElement('div');m.className='msg '+who;m.textContent=txt;
  chat.appendChild(m);chat.scrollTop=chat.scrollHeight;
}
function askChip(q){document.getElementById('advisor-input').value=q;askAdvisor(new Event('x'));}
function askAdvisor(ev){
  ev.preventDefault?.();
  const inp=document.getElementById('advisor-input');
  const q=(inp.value||'').trim();if(!q)return;
  inp.value='';
  pushMsg(q,'user');
  setTimeout(()=>pushMsg(answer(q),'bot'),350);
}
function answer(qRaw){
  const q=qRaw.toLowerCase();
  const tm=thisMonthEntries();
  const inc=sumInBase(tm,'income'),exp=sumInBase(tm,'expense');
  const surplus=inc-exp;
  const months=lastNMonths(6);
  const histInc=[],histExp=[];
  months.forEach(m=>{const es=DB.entries.filter(e=>e.date.startsWith(ymOf(m)));
    histInc.push(sumInBase(es,'income'));histExp.push(sumInBase(es,'expense'));});
  const avgInc=histInc.reduce((a,b)=>a+b,0)/histInc.length||0;
  const avgExp=histExp.reduce((a,b)=>a+b,0)/histExp.length||0;
  const avgSurplus=avgInc-avgExp;
  const money=x=>fmt(x);

  // extract amount from question ("$1200", "1,200", "1200")
  let amt=null;const am=qRaw.match(/(?:[$€£]|aed|usd|eur|gbp)?\s?([\d,]+(?:\.\d+)?)\s*(?:k\b)?/i);
  if(am){let n=parseFloat(am[1].replace(/,/g,''));if(/k\b/i.test(am[0]))n*=1000;if(n>0)amt=n;}

  // detect intent
  const has=w=>q.includes(w);
  const trip=has('trip')||has('travel')||has('holiday')||has('vacation')||has('paris')||has('japan')||has('flight');
  const phone=has('phone')||has('laptop')||has('ipad')||has('tablet')||has('watch')||has('tv')||has('console')||has('ps5')||has('xbox')||has('camera');
  const house=has('house')||has('home')||has('mortgage')||has('apartment')||has('property')||has('flat');
  const car=has('car')||has('vehicle');
  const saveQ=has('save')&&!amt;
  const debt=has('loan')||has('debt')||has('credit');

  const goalHint=name=>DB.goals.find(g=>g.name.toLowerCase().includes(name));

  if(trip){
    const est=amt||(goalHint('paris')?.target)||(goalHint('japan')?.target)||3000;
    const monthsLeft=avgSurplus>0?est/avgSurplus:Infinity;
    const goal=DB.goals.find(g=>/paris|holiday|travel|japan|trip/i.test(g.name));
    let extra=goal?`\n\nYou already have "${goal.name}": ${money(goal.saved)} of ${money(goal.target)} saved (${Math.round(goal.saved/goal.target*100)}%), contributing ${money(goal.monthly)}/mo.`:'';
    if(avgSurplus<=0)return `Right now, no — not comfortably.\n\nThis month you spent more than you earned (deficit ${money(Math.abs(surplus))}). Average monthly surplus over the last 6 months is ${money(avgSurplus)}. Before planning a ${money(est)} trip, we'd want positive cash flow.${extra}`;
    if(monthsLeft<=12)return `Yes ✅ — you can afford it.\n\nA ${money(est)} trip is within reach:\n• Avg monthly income: ${money(avgInc)}\n• Avg monthly expenses: ${money(avgExp)}\n• Free cash flow: ~${money(avgSurplus)}/mo\n\nYou'd fund it in ~${monthsLeft.toFixed(1)} months without touching savings.${extra}\n\nTip: create a Goal tab entry so progress tracks automatically.`;
    return `Almost — but it needs patience.\n\nFree cash flow is ~${money(avgSurplus)}/mo, so ${money(est)} takes ~${monthsLeft.toFixed(0)} months. Options:\n• Trim discretionary spending (check Budgets)\n• Save for a slightly later travel window\n• Aim lower or use points/cards with travel rewards (see Credit Cards).`;
  }
  if(phone){
    const price=amt||900;
    const verdict=surplus>=price?'Yes ✅':'Not from this month\'s surplus alone ⚠️';
    return `${verdict}\n\nA ${money(price)} purchase vs your numbers:\n• This month's free cash flow: ${money(surplus)}\n• Emergency fund goal coverage: ${DB.goals.find(g=>/emergency/i.test(g.name))?money(DB.goals.find(g=>/emergency/i.test(g.name)).saved)+' of target':'no emergency goal set'}\n\n${surplus>=price?'You can buy it outright without debt — go for it.':'Better path: spread it over '+(price/Math.max(avgSurplus,1)).toFixed(1)+' months of saving, or use a 0% installment plan rather than revolving credit-card debt.'}`;
  }
  if(house){
    const price=amt||avgInc*60; // rough affordability heuristic
    const maxMortgage=avgSurplus>0?avgSurplus*0.85:0; // keep buffer
    const downNeeded=price*0.2;
    return `Here's the honest picture for a house around ${money(price)}:\n\n• Avg income: ${money(avgInc)}/mo\n• Avg expenses: ${money(avgExp)}/mo\n• Safe monthly housing budget (≈35% of income): ${money(avgInc*0.35)}\n• Est. mortgage capacity at that budget: ~${money(maxMortgage*130)} principal over 25 yrs (rate-dependent)\n• 20% down payment needed: ${money(downNeeded)}\n• Current liquid assets: ${money(DB.assets.filter(a=>/bank|investment|cash|saving/i.test(a.category+a.name)).reduce((s,a)=>s+a.value,0))}\n\n${downNeeded<DB.assets.filter(a=>/bank|investment/i.test(a.category+a.name)).reduce((s,a)=>s+a.value,0)?'Your savings could cover a down payment today — talk to a lender for exact rates.':'Gap: keep building the down payment — roughly '+Math.ceil(downNeeded/Math.max(avgSurplus,1))+' months at current surplus.'}\n\nNote: figures are heuristics from YOUR data — confirm with a mortgage advisor.`;
  }
  if(car){
    const price=amt||25000;
    return `Car affordability check for ~${money(price)}:\n\n• Rule of thumb: keep total car cost under 15% of take-home → ${money(avgInc*0.15)}/mo\n• Your free cash flow: ${money(avgSurplus)}/mo\n${DB.loans.length?'• Existing EMIs already consume '+money(DB.loans.reduce((a,l)=>a+l.emi,0))+'/mo':''}\n\n${avgSurplus*0.6>price*0.02?'✅ You can support financing of roughly '+money(avgSurplus*0.6)+' EMI/month comfortably.':'⚠️ Tight — consider a cheaper model or bigger down payment.'}`;
  }
  if(saveQ||has('how much')){
    return `Based on your last 6 months:\n\n• Average income: ${money(avgInc)}\n• Average expenses: ${money(avgExp)}\n• Average free cash flow: ${money(avgSurplus)}\n\nSafe monthly savings: ~${money(Math.max(avgSurplus*0.8,0))}\n(keeping a 20% buffer for surprises)\n\nYour current savings rate this month: ${inc>0?((surplus/inc)*100).toFixed(1):0}% — healthy is 20%+.`;
  }
  if(debt){
    const out=DB.loans.reduce((a,l)=>a+l.outstanding,0);
    const emi=DB.loans.reduce((a,l)=>a+l.emi,0);
    return `Debt snapshot:\n• Total outstanding: ${money(out)}\n• Total monthly EMI: ${money(emi)} (${inc>0?(emi/inc*100).toFixed(0):'?'}% of this month's income)\n\nGuideline: keep EMIs under 35% of income. ${emi>avgInc*0.35?'⚠️ You are above that line — prioritize paying down the highest-rate loan.':'✅ Within a healthy range.'}`;
  }
  if(has('afford')&&amt!=null){
    const verdict=surplus>=amt;
    return `${verdict?'Yes ✅':'Probably not this month ⚠️'}\n\nAsking about ${money(amt)}:\n• Free cash flow this month: ${money(surplus)}\n• Average free cash flow: ${money(avgSurplus)}\n\n${verdict?'It fits within this month\'s surplus.':'Shortfall of about '+money(amt-surplus)+'. Save for '+Math.ceil((amt-Math.max(surplus,0))/Math.max(avgSurplus,1))+' more month(s), or trim a budget category first.'}`;
  }
  // fallback summary
  return `Here's where you stand right now:\n\n• Income this month: ${money(inc)}\n• Expenses this month: ${money(exp)}\n• Net: ${money(surplus)}\n• Savings rate: ${inc>0?((surplus/inc)*100).toFixed(1):0}%\n${DB.snapshots.length?'• Latest net worth: '+money(DB.snapshots[DB.snapshots.length-1].assets-DB.snapshots[DB.snapshots.length-1].liabilities):''}\n\nAsk me things like "Can I afford a $1,200 laptop?", "Can I afford to travel to Paris?", "Can I buy a house?" or "How much can I safely save each month?"`;
}
