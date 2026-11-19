/* 逆向工程复习站 app.js
   结构：工具 → 加密 → 密码门 → 账号 → 同步 → 存储 → 题目渲染 → 视图 → PDF阅读 → 上传 → 路由 */
"use strict";

/* ================= 小工具 ================= */
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const TE = new TextEncoder(), TD = new TextDecoder();
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n/1024).toFixed(1) + ' KB' : (n/1048576).toFixed(1) + ' MB';
const fmtTime = t => { const d = new Date(t); const p = x => String(x).padStart(2,'0'); return `${d.getMonth()+1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };
function b64e(buf){ const u = new Uint8Array(buf); let s=''; for(let i=0;i<u.length;i+=0x8000) s += String.fromCharCode.apply(null, u.subarray(i,i+0x8000)); return btoa(s); }
function b64d(str){ const s = atob(str); const u = new Uint8Array(s.length); for(let i=0;i<s.length;i++) u[i]=s.charCodeAt(i); return u; }
function toast(msg, err){ const t = $('#toast'); t.textContent = msg; t.classList.toggle('err', !!err); t.classList.remove('hidden'); clearTimeout(toast._t); toast._t = setTimeout(()=>t.classList.add('hidden'), 2200); }
function modal(html){ $('#modal-body').innerHTML = html; $('#modal').classList.remove('hidden'); }
function closeModal(){ $('#modal').classList.add('hidden'); $('#modal-body').innerHTML=''; }
function confirmBox(title, text, onOk, okLabel='确定', danger=true){
  modal(`<h3 style="font-size:17px;margin-bottom:8px">${esc(title)}</h3>
    <p style="color:var(--sub);font-size:14px;margin-bottom:18px">${esc(text)}</p>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" id="cf-no">取消</button>
      <button class="btn ${danger?'btn-danger':'btn-primary'} btn-sm" id="cf-ok">${esc(okLabel)}</button>
    </div>`);
  $('#cf-no').onclick = closeModal;
  $('#cf-ok').onclick = () => { closeModal(); onOk(); };
}

/* ================= 加密 ================= */
const KDF_ITER_CONTENT = 600000, KDF_ITER_SYNC = 120000;
async function deriveAesKey(password, saltU8, iterations){
  const base = await crypto.subtle.importKey('raw', TE.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt:saltU8, iterations, hash:'SHA-256'}, base,
    {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
}
async function deriveBits(password, saltU8, iterations, bits=256){
  const base = await crypto.subtle.importKey('raw', TE.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2', salt:saltU8, iterations, hash:'SHA-256'}, base, bits));
}
async function aesEnc(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, TE.encode(JSON.stringify(obj)));
  return { iv: b64e(iv), data: b64e(ct) };
}
async function aesDec(key, ivB64, dataB64){
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d(ivB64)}, key, b64d(dataB64));
  return JSON.parse(TD.decode(pt));
}
async function hmacSign(rawKeyU8, msgStr){
  const k = await crypto.subtle.importKey('raw', rawKeyU8, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  return b64e(await crypto.subtle.sign('HMAC', k, TE.encode(msgStr)));
}
async function hmacVerify(rawKeyU8, msgStr, sigB64){
  const expect = await hmacSign(rawKeyU8, msgStr);
  if (expect.length !== sigB64.length) return false;
  let diff = 0; for (let i=0;i<expect.length;i++) diff |= expect.charCodeAt(i) ^ sigB64.charCodeAt(i);
  return diff === 0;
}
async function sha256hex(str){
  const d = await crypto.subtle.digest('SHA-256', TE.encode(str));
  return Array.from(new Uint8Array(d)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

/* ================= 全局状态 ================= */
const S = {
  contentKey: null,   // CryptoKey（网站密码派生）
  bundle: null,       // {site, meta, docs, sync, questions}
  user: null,         // {name, syncKeyU8|null, guest}
  store: null,        // 当前账号数据
  sync: { timer:null, busy:false, lastOk: Number(localStorage.getItem('rr_lastSync')||0), err:'' },
  quiz: null,         // 做题会话
  reciteMasked: null, // null=尚未初始化（首次进入读设置）
  reciteRevealed: new Set(),
};
const qById = {}; // id -> question
function blankAnswers(q){ return q.parts.filter(p => typeof p === 'object').map(p => p.a); }
function normAns(s){ return String(s||'').trim().replace(/\s+/g,'').toLowerCase().replace(/，/g,',').replace(/；/g,';'); }

/* ================= 密码门（内容解密） ================= */
async function fetchJSON(path){ const r = await fetch(path, {cache:'no-cache'}); if(!r.ok) throw new Error('加载失败 '+r.status); return r.json(); }

async function tryUnlock(pw, encFile){
  const salt = b64d(encFile.salt);
  const key = await deriveAesKey(pw, salt, encFile.iter || KDF_ITER_CONTENT);
  const bundle = await aesDec(key, encFile.iv, encFile.data); // 抛异常=密码错误
  return {key, bundle};
}
async function unlockFlow(pw){
  const encFile = await fetchJSON('data/bundle.enc');
  const {key, bundle} = await tryUnlock(pw, encFile);
  S.contentKey = key; S.bundle = bundle;
  bundle.questions.forEach(q => qById[q.id] = q);
  try { sessionStorage.setItem('rr_key', JSON.stringify({salt:encFile.salt, iter:encFile.iter||KDF_ITER_CONTENT, key:b64e(await crypto.subtle.exportKey('raw', key))})); } catch(e){}
}
async function resumeUnlock(){
  const saved = sessionStorage.getItem('rr_key');
  if (!saved) return false;
  try {
    const {salt, iter, key} = JSON.parse(saved);
    const k = await crypto.subtle.importKey('raw', b64d(key), {name:'AES-GCM'}, false, ['encrypt','decrypt']);
    const encFile = await fetchJSON('data/bundle.enc');
    const bundle = await aesDec(k, encFile.iv, encFile.data);
    S.contentKey = k; S.bundle = bundle;
    bundle.questions.forEach(q => qById[q.id] = q);
    return true;
  } catch(e){ sessionStorage.removeItem('rr_key'); return false; }
}

/* ================= 账号（本地档案） ================= */
function loadProfiles(){ try { return JSON.parse(localStorage.getItem('rr_profiles')||'{}'); } catch(e){ return {}; } }
function saveProfiles(p){ localStorage.setItem('rr_profiles', JSON.stringify(p)); }
async function accountVerifier(pw, saltB64){
  const bits = await deriveBits(pw, b64d(saltB64), 60000, 256);
  return b64e(bits);
}
async function loginAccount(name, pw, create){
  const profiles = loadProfiles();
  if (profiles[name]){
    const v = await accountVerifier(pw, profiles[name].salt);
    if (v !== profiles[name].hash) throw new Error('密码不正确');
  } else {
    if (!create) throw new Error('账号不存在');
    const salt = b64e(crypto.getRandomValues(new Uint8Array(16)));
    profiles[name] = { salt, hash: await accountVerifier(pw, salt), created: Date.now() };
    saveProfiles(profiles);
  }
  const syncBits = await deriveBits(pw + '|' + name, TE.encode('rr-sync-v1:'+name), KDF_ITER_SYNC, 256);
  return { name, syncKeyU8: syncBits, syncKeyB64: b64e(syncBits), guest: false };
}

/* ================= 每账号数据存储 ================= */
function storeKey(name){ return 'rr_store_v2_' + name; }
function defaultStore(){ return { wrong:[], progress:{}, mastered:{}, removed:{}, removedUploads:{}, settings:{autoWrong:false, maskDefault:false}, uploadsMeta:[], updatedAt:0 }; }
function loadStore(name){
  try { const raw = JSON.parse(localStorage.getItem(storeKey(name)) || 'null'); return raw ? Object.assign(defaultStore(), raw) : defaultStore(); }
  catch(e){ return defaultStore(); }
}
function saveStore(){
  if (!S.user || !S.store) return;
  S.store.updatedAt = Date.now();
  localStorage.setItem(storeKey(S.user.name), JSON.stringify(S.store));
  scheduleSync();
}

/* ================= 云同步（textdb.dev + 同步码兜底） ================= */
function syncURL(){ return `https://textdb.dev/api/data/${S.bundle.sync.docId}/`; }
async function syncReadAll(){
  const r = await fetch(syncURL(), {cache:'no-store'});
  const txt = (await r.text()).trim();
  if (!txt) return {v:1, accounts:{}};
  try { const j = JSON.parse(txt); return (j && j.accounts) ? j : {v:1, accounts:{}}; } catch(e){ return {v:1, accounts:{}}; }
}
async function syncWriteAll(all){
  const r = await fetch(syncURL(), {method:'POST', headers:{'Content-Type':'text/plain'}, body: JSON.stringify(all)});
  if (!r.ok) throw new Error('同步服务返回 '+r.status);
}
function mergeStores(local, cloud){
  const m = JSON.parse(JSON.stringify(local));
  m.wrong = [...local.wrong];
  const byId = a => { const o={}; a.forEach(w=>{ if(!o[w.qid] || o[w.qid].t < w.t) o[w.qid]=w; }); return o; };
  const wl = byId(local.wrong), wc = byId(cloud.wrong||[]);
  Object.values({...wl, ...wc}).forEach(w => { const cur = wl[w.qid]; if(!cur || w.t >= cur.t) { m.wrong = m.wrong.filter(x=>x.qid!==w.qid); m.wrong.push(w); } });
  m.removed = {...(local.removed||{}), ...(cloud.removed||{})};
  m.wrong = m.wrong.filter(w => !m.removed[w.qid] || (w.t||0) > m.removed[w.qid]);
  m.progress = {...local.progress};
  Object.entries(cloud.progress||{}).forEach(([k,v]) => { if(!m.progress[k] || (v.t||0) >= (m.progress[k].t||0)) m.progress[k]=v; });
  m.mastered = {...local.mastered};
  Object.entries(cloud.mastered||{}).forEach(([k,v]) => { if(!m.mastered[k] || (v.t||0) >= (m.mastered[k].t||0)) m.mastered[k]=v; });
  if ((cloud.updatedAt||0) > (local.updatedAt||0)) m.settings = {...local.settings, ...(cloud.settings||{})};
  const ul = [...local.uploadsMeta], um = {};
  ul.forEach(u=>um[u.id]=u);
  (cloud.uploadsMeta||[]).forEach(u => { if(!um[u.id] || (u.addedAt||0) >= (um[u.id].addedAt||0)) um[u.id]=u; });
  m.removedUploads = {...(local.removedUploads||{}), ...(cloud.removedUploads||{})};
  m.uploadsMeta = Object.values(um).filter(u => (m.removedUploads[u.id]||0) < (u.addedAt||0) || !m.removedUploads[u.id]);
  m.updatedAt = Math.max(local.updatedAt||0, cloud.updatedAt||0);
  return m;
}

/* —— 同步密钥直接作为 AES-GCM 密钥使用 —— */
async function syncKeyToAes(){
  return crypto.subtle.importKey('raw', S.user.syncKeyU8, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
async function doSync(manual){
  if (!S.user || S.user.guest) { if(manual) toast('游客模式不参与同步', true); return; }
  if (S.sync.busy) return;
  S.sync.busy = true; setSyncBadge('busy','同步中…');
  try {
    const all = await syncReadAll();
    const aesKey = await syncKeyToAes();
    const enc = await aesEnc(aesKey, S.store);
    enc.hmac = await hmacSign(S.user.syncKeyU8, enc.data);
    enc.t = Date.now();
    const rec = all.accounts?.[S.user.name];
    if (rec && rec.data && rec.hmac){
      const ok = await hmacVerify(S.user.syncKeyU8, rec.data, rec.hmac);
      if (ok){
        const cloud = await aesDec(aesKey, rec.iv, rec.data);
        S.store = mergeStores(S.store, cloud);
        localStorage.setItem(storeKey(S.user.name), JSON.stringify(S.store));
      } else if (!manual) {
        // 云端记录校验失败（可能是他人数据或损坏），保留本地，仅覆盖自己的槽位
      }
    }
    all.v = 1; all.accounts = all.accounts || {}; all.accounts[S.user.name] = enc;
    await syncWriteAll(all);
    S.sync.lastOk = Date.now(); S.sync.err = '';
    localStorage.setItem('rr_lastSync', String(S.sync.lastOk));
    setSyncBadge('ok', '已同步 ' + fmtTime(S.sync.lastOk));
    if (manual) toast('同步完成 ✓');
    if (S.view === 'home' || S.view === 'settings') renderRoute();
  } catch(e){
    S.sync.err = e.message || String(e);
    setSyncBadge('err', '同步失败');
    if (manual) toast('同步失败：' + S.sync.err + '（可稍后重试或导出同步码）', true);
  } finally { S.sync.busy = false; }
}
function scheduleSync(){ clearTimeout(S.sync.timer); S.sync.timer = setTimeout(()=>doSync(false), 2200); }
function setSyncBadge(cls, text){ const b = $('#sync-badge'); b.className = 'sync-badge ' + cls; b.textContent = text; if (cls==='') { b.className='sync-badge'; b.textContent='·'; } }

/* 同步码（手动兜底） */
async function exportSyncCode(){
  const aesKey = await syncKeyToAes();
  const enc = await aesEnc(aesKey, S.store);
  enc.u = S.user.name; enc.k = 'rr-code-v1';
  const code = btoa(unescape(encodeURIComponent(JSON.stringify(enc))));
  modal(`<h3 style="font-size:17px;margin-bottom:8px">导出同步码</h3>
    <p style="color:var(--sub);font-size:13px;margin-bottom:12px">把这段代码复制到另一台设备，在登录同一账号后于「设置 → 导入同步码」粘贴导入。代码含账号加密数据，请勿泄露。</p>
    <textarea id="code-ta" style="width:100%;height:130px;font-size:12px;font-family:Menlo,monospace;border:1.5px solid var(--line);border-radius:10px;padding:10px">${esc(code)}</textarea>
    <div style="display:flex;gap:10px;margin-top:12px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">关闭</button>
      <button class="btn btn-primary btn-sm" id="code-copy">复制</button></div>`);
  $('#code-copy').onclick = async () => { await navigator.clipboard.writeText(code); toast('已复制到剪贴板'); };
}
async function importSyncCode(){
  modal(`<h3 style="font-size:17px;margin-bottom:8px">导入同步码</h3>
    <p style="color:var(--sub);font-size:13px;margin-bottom:12px">粘贴从另一台设备导出的同步码：</p>
    <textarea id="code-in" style="width:100%;height:130px;font-size:12px;font-family:Menlo,monospace;border:1.5px solid var(--line);border-radius:10px;padding:10px" placeholder="粘贴同步码"></textarea>
    <div style="display:flex;gap:10px;margin-top:12px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">取消</button>
      <button class="btn btn-primary btn-sm" id="code-imp">导入</button></div>`);
  $('#code-imp').onclick = async () => {
    try {
      const raw = decodeURIComponent(escape(atob($('#code-in').value.trim())));
      const enc = JSON.parse(raw);
      if (enc.k !== 'rr-code-v1') throw new Error('格式不对');
      const aesKey = await syncKeyToAes();
      const cloud = await aesDec(aesKey, enc.iv, enc.data);
      S.store = mergeStores(S.store, cloud);
      saveStore(); closeModal(); toast('导入成功 ✓'); renderRoute();
    } catch(e){ toast('导入失败：' + e.message, true); }
  };
}

/* ================= 题目渲染 ================= */
function chipType(q){ return `<span class="chip type-${q.type}">${S.bundle.meta.typeNames[q.type]}</span>`; }
function chipCh(q){ return `<span class="chip ch${q.ch}">${S.bundle.meta.chapters[q.ch]}</span>`; }
function stemHTML(q, {masked=false, quiz=false} = {}){
  let h = '';
  if (q.type === 'blank'){
    h = '<span class="stem">' + q.parts.map(p => {
      if (typeof p === 'string') return esc(p);
      if (quiz) return `<input class="blank-in" data-bi="${p.a}" size="${Math.max(6, p.a.length+4)}" autocomplete="off">`;
      return masked ? `<span class="blank-cover">＿＿＿</span>` : `<span class="blank-fill">${esc(p.a)}</span>`;
    }).join('') + '</span>';
  } else {
    h = `<div class="stem">${esc(q.stem)}</div>`;
    if (q.code) h += `<div class="codeblock">${esc(q.code)}</div>`;
    if (q.table) h += `<div class="tableblock">${esc(q.table)}</div>`;
  }
  return h;
}
function optionsHTML(q, {quiz=false, revealed=false, picked=null} = {}){
  if (q.type !== 'single') return '';
  let h = '<div class="opts">';
  for (const [k, t] of q.options){
    let cls = 'opt';
    if (quiz) { if (picked === k) cls += ' sel'; }
    else if (revealed) { if (k === q.ans) cls += ' ok'; if (picked === k && picked !== q.ans) cls += ' bad'; if (picked === k) cls += ' sel'; }
    if (revealed || !quiz) cls += ' locked';
    h += `<button class="${cls}" data-k="${k}"><span class="k">${k}</span><span>${esc(t)}</span></button>`;
  }
  return h + '</div>';
}
function judgeHTML(q, {quiz=false, revealed=false, picked=null} = {}){
  if (q.type !== 'judge') return '';
  let h = '<div class="judge-row">';
  for (const k of ['对','错']){
    let cls = 'judge-btn';
    if (quiz) { if (picked === k) cls += ' sel'; }
    else if (revealed) { if (k === q.ans) cls += ' ok'; if (picked === k && picked !== q.ans) cls += ' bad'; if (picked === k) cls += ' sel'; }
    if (revealed || !quiz) cls += ' locked';
    h += `<button class="${cls}" data-k="${k}">${k}</button>`;
  }
  return h + '</div>';
}
function answerText(q){
  switch(q.type){
    case 'blank': return blankAnswers(q).join('、');
    case 'single': return q.ans;
    case 'judge': return q.ans;
    default: return '';
  }
}
function answerBlockHTML(q, {masked=false, revealed=false, showNote=true} = {}){
  if (q.type === 'blank'){
    const pills = blankAnswers(q).map(a=>`<span class="ans-pill">${esc(a)}</span>`).join('');
    return `<div class="lbl">答案（按原卷下划线挖空）</div><div class="ans-blank-list ans-mask-target">${pills}</div>`;
  }
  if (q.type === 'single' || q.type === 'judge'){
    return `<div class="lbl">正确答案</div><div class="ans-text ans-mask-target"><b style="color:var(--accent-deep)">${esc(answerText(q))}</b></div>`;
  }
  let h = `<div class="lbl">参考答案</div><div class="ans-text ans-mask-target">${esc(q.ref)}</div>`;
  if (showNote && q.refNote) h += `<div class="q-note">${esc(q.refNote)}</div>`;
  return h;
}
function starBtnHTML(q, cls='btn btn-star btn-sm'){
  const inWrong = S.store && S.store.wrong.some(w => w.qid === q.id);
  return `<button class="${cls}${inWrong?' on':''}" data-star="${q.id}" title="${inWrong?'移出错题本':'加入错题本'}">${inWrong?'★ 已在错题本':'☆ 加入错题本'}</button>`;
}
function bindStarEvents(root){
  root.querySelectorAll('[data-star]').forEach(btn => {
    btn.onclick = () => {
      const qid = btn.dataset.star;
      const i = S.store.wrong.findIndex(w => w.qid === qid);
      if (i >= 0){ S.store.wrong.splice(i,1); S.store.removed[qid] = Date.now(); toast('已移出错题本'); }
      else { delete S.store.removed[qid]; S.store.wrong.push({qid, t:Date.now(), src:S.view==='recite'?'背题':(S.view==='quiz'?'做题':S.view||'手动')}); toast('已加入错题本 ★'); }
      saveStore();
      btn.classList.toggle('on'); 
      btn.innerHTML = btn.classList.contains('on') ? '★ 已在错题本' : '☆ 加入错题本';
      if (S.view === 'wrong') renderRoute();
    };
  });
}

/* ================= 背题模式 ================= */
function reciteFiltered(){
  const f = reciteFilter;
  return S.bundle.questions.filter(q => {
    if (f.type !== 'all' && q.type !== f.type) return false;
    if (f.ch !== 'all' && String(q.ch) !== f.ch) return false;
    if (f.onlyWrong && !S.store.wrong.some(w=>w.qid===q.id)) return false;
    if (f.kw){
      const hay = (q.type==='blank' ? q.parts.map(p=>typeof p==='string'?p:p.a).join('') : (q.stem||'') + (q.code||'') + (q.ref||''));
      if (!hay.includes(f.kw)) return false;
    }
    return true;
  });
}
const reciteFilter = { type:'all', ch:'all', kw:'', onlyWrong:false };
function renderRecite(root){
  if (S.reciteMasked === null) S.reciteMasked = !!S.store.settings.maskDefault;
  const list = reciteFiltered();
  root.innerHTML = `
    <div class="page-title">背题模式</div>
    <div class="page-sub">答案直接显示，配合「遮挡答案」自测记忆；点击每题的遮挡层可单独查看。</div>
    <div class="filterbar">
      <select id="rf-type"><option value="all">全部题型</option>${S.bundle.meta.typeOrder.map(t=>`<option value="${t}">${S.bundle.meta.typeNames[t]}</option>`).join('')}</select>
      <select id="rf-ch"><option value="all">全部章节</option><option value="2">第2章</option><option value="7">第7章</option></select>
      <input type="text" id="rf-kw" placeholder="搜索关键词" style="width:150px">
      <button class="btn btn-ghost btn-sm" id="rf-ow">只看错题</button>
      <span class="spacer"></span>
      <span class="seg" id="rf-mask"><button id="rf-mask-off" class="${!S.reciteMasked?'on':''}">显示答案</button><button id="rf-mask-on" class="${S.reciteMasked?'on':''}">遮挡答案</button></span>
      <span style="font-size:13px;color:var(--sub)">共 ${list.length} 题</span>
    </div>
    <div id="recite-list"></div>`;
  $('#rf-type').value = reciteFilter.type; $('#rf-ch').value = reciteFilter.ch; $('#rf-kw').value = reciteFilter.kw;
  $('#rf-ow').classList.toggle('on', reciteFilter.onlyWrong);
  $('#rf-type').onchange = e => { reciteFilter.type = e.target.value; renderRoute(); };
  $('#rf-ch').onchange = e => { reciteFilter.ch = e.target.value; renderRoute(); };
  $('#rf-kw').oninput = e => { reciteFilter.kw = e.target.value.trim(); renderRoute(); };
  $('#rf-ow').onclick = () => { reciteFilter.onlyWrong = !reciteFilter.onlyWrong; renderRoute(); };
  $('#rf-mask-on').onclick = () => { S.reciteMasked = true; renderRoute(); };
  $('#rf-mask-off').onclick = () => { S.reciteMasked = false; renderRoute(); };
  const wrap = $('#recite-list');
  if (!list.length){ wrap.innerHTML = `<div class="empty"><div class="big">✦</div>没有符合条件的题目</div>`; return; }
  wrap.innerHTML = list.map(q => reciteCardHTML(q)).join('');
  bindCardEvents(wrap);
}
function reciteCardHTML(q){
  const masked = S.reciteMasked && !S.reciteRevealed.has(q.id);
  const body = (q.type === 'blank')
    ? stemHTML(q, {masked})
    : stemHTML(q) + optionsHTML(q, {revealed:!masked, picked:null}) + judgeHTML(q, {revealed:!masked, picked:null});
  return `<div class="card card-q" data-q="${q.id}">
    <div class="q-head">${chipType(q)}${chipCh(q)}<span class="chip no-chip">${q.type==='blank'?`第 ${q.no} 题`:`第 ${q.no} 题`}</span><span class="src-tag">${esc(q.src||'')}</span></div>
    ${body}
    <div class="answer-box ${masked?'masked':''}" style="position:relative">
      ${answerBlockHTML(q, {showNote:true})}
      ${masked ? `<div class="ans-cover"><button data-peek="${q.id}">点击查看答案</button></div>` : ''}
    </div>
    ${q.note ? `<div class="q-note">${esc(q.note)}</div>` : ''}
    <div class="q-actions">${starBtnHTML(q)}</div>
  </div>`;
}
function bindCardEvents(root){
  root.querySelectorAll('[data-peek]').forEach(b => b.onclick = () => { S.reciteRevealed.add(b.dataset.peek); renderRoute(); });
  bindStarEvents(root);
}

/* ================= 做题模式 ================= */
function renderQuiz(root){
  if (!S.quiz){ renderQuizSetup(root); return; }
  renderQuizRun(root);
}
let quizFilter = { type:'all', ch:'all', scope:'all', count:'all', shuffle:true };
function renderQuizSetup(root){
  const total = S.bundle.questions.length;
  root.innerHTML = `
    <div class="page-title">做题模式</div>
    <div class="page-sub">正式答题后，点击「下一题」才会显示正确答案；答错的题可一键加入错题本。</div>
    <div class="card">
      <div class="filterbar" style="margin-bottom:12px">
        <select id="qf-type"><option value="all">全部题型</option>${S.bundle.meta.typeOrder.map(t=>`<option value="${t}">${S.bundle.meta.typeNames[t]}</option>`).join('')}</select>
        <select id="qf-ch"><option value="all">全部章节</option><option value="2">第2章</option><option value="7">第7章</option></select>
        <select id="qf-scope"><option value="all">全部题目</option><option value="undo">只做未做过</option><option value="wrong">错题重练</option></select>
        <select id="qf-count"><option value="all">不限题数</option><option value="5">5 题</option><option value="10">10 题</option><option value="20">20 题</option></select>
      </div>
      <label style="display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--sub)">
        <input type="checkbox" id="qf-shuffle" checked style="width:16px;height:16px;accent-color:var(--accent)"> 打乱顺序
      </label>
      <button class="btn btn-primary" id="qf-start" style="margin-top:14px">开始练习</button>
    </div>
    <div class="card"><b>题型分布</b><div class="type-dist" style="margin-top:10px">${S.bundle.meta.typeOrder.map(t=>{
      const c = S.bundle.questions.filter(q=>q.type===t).length;
      return `<div class="dist-row"><span class="nm">${S.bundle.meta.typeNames[t]}</span><span class="bar"><i style="width:${(c/total*100).toFixed(1)}%"></i></span><span class="ct">${c}</span></div>`;
    }).join('')}</div></div>`;
  $('#qf-type').value = quizFilter.type; $('#qf-ch').value = quizFilter.ch; $('#qf-scope').value = quizFilter.scope; $('#qf-count').value = quizFilter.count;
  $('#qf-shuffle').checked = quizFilter.shuffle;
  $('#qf-start').onclick = () => {
    quizFilter = { type:$('#qf-type').value, ch:$('#qf-ch').value, scope:$('#qf-scope').value, count:$('#qf-count').value, shuffle:$('#qf-shuffle').checked };
    let pool = S.bundle.questions.filter(q => {
      if (quizFilter.type !== 'all' && q.type !== quizFilter.type) return false;
      if (quizFilter.ch !== 'all' && String(q.ch) !== quizFilter.ch) return false;
      if (quizFilter.scope === 'undo' && S.store.progress[q.id]) return false;
      if (quizFilter.scope === 'wrong' && !S.store.wrong.some(w=>w.qid===q.id)) return false;
      return true;
    });
    if (quizFilter.shuffle) pool = pool.slice().sort(() => Math.random() - 0.5);
    if (quizFilter.count !== 'all') pool = pool.slice(0, parseInt(quizFilter.count, 10));
    if (!pool.length){ toast('没有符合条件的题目', true); return; }
    S.quiz = { ids: pool.map(q=>q.id), idx:0, picked:null, inputs:{}, revealed:false, results:[], scope:quizFilter.scope };
    location.hash = '#/quiz'; renderRoute();
  };
}
function quizQ(){ return qById[S.quiz.ids[S.quiz.idx]]; }
function renderQuizRun(root){
  const q = quizQ(); if (!q) return finishQuiz(root);
  const z = S.quiz, done = z.revealed;
  const prog = Math.round(((z.idx) / z.ids.length) * 100);
  let inputHTML = '';
  if (q.type === 'single') inputHTML = optionsHTML(q, {quiz:!done, revealed:done, picked:z.picked});
  else if (q.type === 'judge') inputHTML = judgeHTML(q, {quiz:!done, revealed:done, picked:z.picked});
  else if (q.type === 'short' || q.type === 'analysis') inputHTML = `<textarea class="answer-area" id="qa-area" placeholder="写下你的答案（可留空直接对照参考答案）">${esc(z.inputs[q.id]||'')}</textarea>`;
  let revealHTML = '';
  if (done){
    const r = z.results[z.idx] || {};
    const good = r.ok === true, subjective = (q.type==='short'||q.type==='analysis');
    const verdict = subjective ? (r.ok===true ? '回答正确' : (r.ok===false ? '回答有误' : '未判定 · 请自评')) : (good ? '回答正确' : '回答错误');
    revealHTML = `<div class="reveal ${r.ok===true?'good':(r.ok===false?'badx':'')}">
      <div class="reveal-head"><span class="verdict ${r.ok===true?'good':(r.ok===false?'badx':'')}">${r.ok===true?'✓':(r.ok===false?'✗':'•')} ${verdict}</span>
        <span style="margin-left:auto">${starBtnHTML(q)}</span></div>
      ${r.detail ? `<div style="font-size:13px;color:var(--sub);margin-top:6px">${esc(r.detail)}</div>` : ''}
      <div class="reveal-ans">${answerBlockHTML(q, {})}</div>
      ${subjective && r.ok == null ? `<div style="display:flex;gap:10px;margin-top:12px">
        <button class="btn btn-ghost btn-sm" id="self-ok">我答对了</button>
        <button class="btn btn-danger btn-sm" id="self-bad">我答错了</button></div>` : ''}
    </div>`;
  }
  root.innerHTML = `
    <div class="page-title">做题模式</div>
    <div class="progress-wrap"><div class="progress-bar"><i style="width:${prog}%"></i></div><span class="progress-num">第 ${z.idx+1} / ${z.ids.length} 题</span></div>
    <div class="card card-q">
      <div class="q-head">${chipType(q)}${chipCh(q)}<span class="chip no-chip">第 ${q.no} 题</span><span class="src-tag">${esc(q.src||'')}</span></div>
      ${stemHTML(q, {quiz: q.type==='blank' && !done})}
      ${q.type==='blank' && done ? `<div class="reveal-ans" style="margin-top:6px"><div class="lbl">你的填写</div><div class="ans-blank-list">${(z.results[z.idx]?.user||[]).map(u=>`<span class="ans-pill" style="color:${u.ok?'var(--ok)':'var(--bad)'}">${esc(u.v||'（空）')}</span>`).join('')}</div></div>` : ''}
      ${inputHTML}
      ${revealHTML}
      ${q.note ? `<div class="q-note">${esc(q.note)}</div>` : ''}
      <div class="q-actions">
        ${!done ? `<button class="btn btn-primary" id="q-next">下一题（提交并显示答案）</button>` :
                  `<button class="btn btn-primary" id="q-next2">${z.idx+1 < z.ids.length ? '下一题' : '查看成绩'}</button>
                   <button class="btn btn-ghost btn-sm" id="q-quit">结束练习</button>`}
      </div>
    </div>`;
  bindQuizEvents(root, q, done);
}
function bindQuizEvents(root, q, done){
  const z = S.quiz;
  if (!done){
    root.querySelectorAll('.opt').forEach(b => b.onclick = () => { z.picked = b.dataset.k; renderRoute(); });
    root.querySelectorAll('.judge-btn').forEach(b => b.onclick = () => { z.picked = b.dataset.k; renderRoute(); });
    const area = $('#qa-area'); if (area) area.oninput = () => { z.inputs[q.id] = area.value; };
    $('#q-next').onclick = () => revealCurrent(root);
  } else {
    const so = $('#self-ok'), sb = $('#self-bad');
    if (so) so.onclick = () => { z.results[z.idx].ok = true; recordProgress(q, true); renderRoute(); };
    if (sb) sb.onclick = () => { z.results[z.idx].ok = false; recordProgress(q, false); renderRoute(); };
    $('#q-next2').onclick = () => {
      z.idx++; z.picked = null; z.revealed = false;
      if (z.idx >= z.ids.length) finishQuiz(root); else renderRoute();
    };
    $('#q-quit').onclick = () => { confirmBox('结束练习？','当前进度结果将保留已答题的记录。', () => { S.quiz = null; renderRoute(); }); };
  }
}
function collectAnswer(q){
  if (q.type === 'single' || q.type === 'judge') return S.quiz.picked;
  if (q.type === 'blank'){ return Array.from($$('#view .blank-in')).map(inp => inp.value); }
  const a = $('#qa-area'); return a ? a.value : '';
}
function checkAnswer(q, ans){
  if (q.type === 'single') return { ok: ans === q.ans, detail: ans ? `你的选择：${ans}` : '未作答' };
  if (q.type === 'judge') return { ok: ans === q.ans, detail: ans ? `你的判断：${ans}` : '未作答' };
  if (q.type === 'blank'){
    const correct = blankAnswers(q);
    const user = Array.isArray(ans) ? ans : [];
    const detail = user.map((u,i) => u ? `${i+1}. ${u}` : `${i+1}.（未填）`).join('　');
    const blanks = user.map((u,i) => ({v:u, ok: normAns(u) === normAns(correct[i])}));
    return { ok: blanks.every(b=>b.ok) && blanks.length === correct.length, detail, blanks };
  }
  return { ok: null, detail: '' };
}
function revealCurrent(root){
  const q = quizQ(), z = S.quiz;
  const ans = collectAnswer(q);
  const r = checkAnswer(q, ans);
  r.user = Array.isArray(ans) ? ans.map((v,i)=>({v, ok:r.blanks?r.blanks[i]?.ok:true})) : null;
  if (q.type === 'blank' && r.blanks){ $$('#view .blank-in').forEach((inp,i)=>{ inp.classList.add(r.blanks[i]?.ok ? 'right' : 'wrong'); inp.disabled = true; }); }
  z.results[z.idx] = r;
  z.revealed = true;
  if (r.ok !== null) recordProgress(q, r.ok);
  renderRoute();
}
function recordProgress(q, ok){
  const z = S.quiz;
  z.results[z.idx] = Object.assign(z.results[z.idx] || {}, {ok});
  S.store.progress[q.id] = { ok, a: typeof collectAnswerSafe(q) === 'string' ? collectAnswerSafe(q).slice(0,80) : '', t: Date.now() };
  if (!ok){
    if (S.store.settings.autoWrong && !S.store.wrong.some(w=>w.qid===q.id)) S.store.wrong.push({qid:q.id, t:Date.now(), src:'做题'});
    else if (!S.store.settings.autoWrong) { /* 手动加入 */ }
  }
  saveStore();
}
function collectAnswerSafe(q){
  try { const a = collectAnswer(q); if (q.type==='blank' && Array.isArray(a)) return a.filter(Boolean).join(' / '); return a || ''; } catch(e){ return ''; }
}
function finishQuiz(root){
  const z = S.quiz;
  const graded = z.results.map((r,i)=>({r, id:z.ids[i]})).filter(x=>x.r && x.r.ok !== null);
  const right = graded.filter(x=>x.r.ok === true).length;
  const rate = graded.length ? Math.round(right / graded.length * 100) : 0;
  const wrongOnes = graded.filter(x=>x.r.ok === false);
  root.innerHTML = `
    <div class="page-title">练习完成</div>
    <div class="card" style="text-align:center;padding:30px">
      <div style="font-family:var(--serif);font-size:46px;font-weight:800;color:${rate>=80?'var(--ok)':rate>=60?'var(--warn)':'var(--bad)'}">${rate}%</div>
      <div style="color:var(--sub);margin-top:6px">客观题正确 ${right} / ${graded.length}${graded.length<z.ids.length?`（另有 ${z.ids.length-graded.length} 题为自评主观题）`:''}</div>
      <div style="display:flex;gap:10px;justify-content:center;margin-top:20px;flex-wrap:wrap">
        ${wrongOnes.length?`<button class="btn btn-primary" id="redo-wrong">重练本次错题（${wrongOnes.length}）</button>`:''}
        <button class="btn btn-ghost" id="quiz-again">再练一组</button>
        <button class="btn btn-ghost" id="quiz-home">返回</button>
      </div>
    </div>
    ${wrongOnes.length?`<div class="section-h">本次错题</div>` + wrongOnes.map(({r,id})=>{
      const q = qById[id];
      return `<div class="card card-q"><div class="q-head">${chipType(q)}${chipCh(q)}<span class="src-tag">${esc(q.src||'')}</span></div>
        ${stemHTML(q)}${optionsHTML(q,{revealed:true,picked:Array.isArray(r.user)?null:(typeof r.detail==='string'&&r.detail.includes('你的选择：')?r.detail.slice(-1):null)})}
        <div class="answer-box">${answerBlockHTML(q,{})}</div></div>`;
    }).join(''):''}`;
  $('#quiz-again').onclick = () => { S.quiz = null; renderRoute(); };
  $('#quiz-home').onclick = () => { S.quiz = null; location.hash = '#/home'; };
  const rw = $('#redo-wrong');
  if (rw) rw.onclick = () => {
    const ids = wrongOnes.map(x=>x.id);
    S.quiz = { ids, idx:0, picked:null, inputs:{}, revealed:false, results:[], scope:'wrong' };
    renderRoute();
  };
}

/* ================= 错题本 ================= */
function renderWrong(root){
  const items = S.store.wrong.slice().sort((a,b)=>b.t-a.t);
  root.innerHTML = `
    <div class="page-title">错题本</div>
    <div class="page-sub">从背题/做题模式点「☆ 加入错题本」，在这里集中复习、自由增删。</div>
    <div class="filterbar">
      <span style="font-size:13.5px;color:var(--sub)">共 <b>${items.length}</b> 题 · 已掌握 <b>${Object.keys(S.store.mastered).length}</b></span>
      <span class="spacer"></span>
      <label style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--sub)"><input type="checkbox" id="w-mask" style="width:15px;height:15px;accent-color:var(--accent)" ${S.reciteMasked?'checked':''}> 遮挡答案</label>
      <button class="btn btn-primary btn-sm" id="w-quiz" ${items.length?'':'disabled'}>重练错题</button>
      <button class="btn btn-danger btn-sm" id="w-clear" ${items.length?'':'disabled'}>清空</button>
    </div>
    <div id="wrong-list"></div>`;
  $('#w-mask').onchange = e => { S.reciteMasked = e.target.checked; renderRoute(); };
  $('#w-quiz').onclick = () => {
    const ids = items.map(w=>w.qid).filter(id=>qById[id]);
    if (!ids.length) return;
    S.quiz = { ids: ids.slice().sort(()=>Math.random()-0.5), idx:0, picked:null, inputs:{}, revealed:false, results:[], scope:'wrong' };
    location.hash = '#/quiz'; renderRoute();
  };
  $('#w-clear').onclick = () => confirmBox('清空错题本？', `将移除全部 ${items.length} 道错题（不影响练习记录）。`, () => { S.store.wrong = []; saveStore(); renderRoute(); toast('错题本已清空'); });
  const wrap = $('#wrong-list');
  if (!items.length){ wrap.innerHTML = `<div class="empty"><div class="big">☆</div>错题本是空的<br><span style="font-size:12.5px">在背题或做题模式中点击「☆ 加入错题本」即可收录</span></div>`; return; }
  wrap.innerHTML = items.map(w => {
    const q = qById[w.qid]; if (!q) return '';
    const masked = S.reciteMasked && !S.reciteRevealed.has(q.id);
    const body = q.type==='blank' ? stemHTML(q,{masked}) : stemHTML(q) + optionsHTML(q,{revealed:!masked,picked:null}) + judgeHTML(q,{revealed:!masked,picked:null});
    return `<div class="card card-q">
      <div class="q-head">${chipType(q)}${chipCh(q)}<span class="src-tag">${esc(q.src||'')} · ${fmtTime(w.t)} 收录${w.src?`（${esc(w.src)}）`:''}</span></div>
      ${body}
      <div class="answer-box ${masked?'masked':''}" style="position:relative">${answerBlockHTML(q,{})}
        ${masked?`<div class="ans-cover"><button data-peek="${q.id}">点击查看答案</button></div>`:''}
      </div>
      <div class="q-actions">
        <button class="btn btn-ghost btn-sm" data-remove="${q.id}">移出</button>
        <button class="btn btn-ghost btn-sm" data-master="${q.id}">✓ 标记已掌握</button>
        ${starBtnHTML(q)}
      </div></div>`;
  }).join('');
  wrap.querySelectorAll('[data-peek]').forEach(b => b.onclick = () => { S.reciteRevealed.add(b.dataset.peek); renderRoute(); });
  wrap.querySelectorAll('[data-remove]').forEach(b => b.onclick = () => {
    const qid = b.dataset.remove;
    S.store.wrong = S.store.wrong.filter(w=>w.qid!==qid);
    S.store.removed[qid] = Date.now();
    saveStore(); renderRoute(); toast('已移出');
  });
  wrap.querySelectorAll('[data-master]').forEach(b => b.onclick = () => {
    const id = b.dataset.master;
    S.store.mastered[id] = Date.now();
    S.store.wrong = S.store.wrong.filter(w=>w.qid!==id);
    S.store.removed[id] = Date.now();
    saveStore(); renderRoute(); toast('已标记掌握，移出错题本 ✓');
  });
}

/* ================= 文档中心 ================= */
function openDB(){
  return new Promise((res, rej) => {
    const rq = indexedDB.open('rrsite', 1);
    rq.onupgradeneeded = () => { rq.result.createObjectStore('files', {keyPath:'id'}); };
    rq.onsuccess = () => res(rq.result);
    rq.onerror = () => rej(rq.error);
  });
}
async function idbPut(rec){ const db = await openDB(); return new Promise((res,rej)=>{ const tx=db.transaction('files','readwrite'); tx.objectStore('files').put(rec); tx.oncomplete=res; tx.onerror=()=>rej(tx.error); }); }
async function idbGet(id){ const db = await openDB(); return new Promise((res,rej)=>{ const tx=db.transaction('files','readonly'); const rq=tx.objectStore('files').get(id); rq.onsuccess=()=>res(rq.result); rq.onerror=()=>rej(rq.error); }); }
async function idbDel(id){ const db = await openDB(); return new Promise((res,rej)=>{ const tx=db.transaction('files','readwrite'); tx.objectStore('files').delete(id); tx.oncomplete=res; tx.onerror=()=>rej(tx.error); }); }

function renderDocs(root){
  const docs = S.bundle.docs;
  const ups = S.store.uploadsMeta.slice().sort((a,b)=>b.addedAt-a.addedAt);
  root.innerHTML = `
    <div class="page-title">文档中心 · 知识库</div>
    <div class="page-sub">在线阅读或下载课程资料；也可以上传你自己的文档保存在站内（≤150KB 的文档会随账号云同步）。</div>
    <div class="section-h">内置资料 <span class="hint">加密存放 · 解锁后可读</span></div>
    <div class="doc-grid">${docs.map((d,i)=>`
      <div class="doc-card">
        <div class="doc-ico">PDF</div>
        <div class="doc-name">${esc(d.name)}</div>
        <div class="doc-meta">${fmtSize(d.size)} · 课件资料</div>
        <div class="doc-actions"><button class="btn btn-primary btn-sm" data-read="${i}">在线阅读</button><button class="btn btn-ghost btn-sm" data-dl="${i}">下载</button></div>
      </div>`).join('')}</div>
    <div class="section-h">我的上传 <span class="hint">保存在本设备；小文件自动云同步</span></div>
    <div class="filterbar"><button class="btn btn-primary btn-sm" id="up-btn">＋ 上传文档</button><input type="file" id="up-input" multiple accept=".pdf,.txt,.md,.png,.jpg,.jpeg,.webp" style="display:none"></div>
    <div class="doc-grid">${ups.length?ups.map(u=>`
      <div class="doc-card">
        <div class="doc-ico ${u.type&&u.type.startsWith('image')?'img':(u.name.endsWith('.pdf')?'':'txt')}">${u.name.endsWith('.pdf')?'PDF':(u.type&&u.type.startsWith('image')?'IMG':'TXT')}</div>
        <div class="doc-name">${esc(u.name)}</div>
        <div class="doc-meta">${fmtSize(u.size)} · ${fmtTime(u.addedAt)}上传 · <span class="doc-sync ${u.syncData?'cloud':'local'}">${u.syncData?'已同步':'仅本设备'}</span></div>
        <div class="doc-actions"><button class="btn btn-primary btn-sm" data-uopen="${u.id}">打开</button><button class="btn btn-ghost btn-sm" data-udl="${u.id}">下载</button><button class="btn btn-danger btn-sm" data-udel="${u.id}">删除</button></div>
      </div>`).join(''):`<div class="empty" style="grid-column:1/-1"><div class="big">⬆</div>还没有上传文档</div>`}</div>`;
  $('#up-btn').onclick = () => $('#up-input').click();
  $('#up-input').onchange = async e => { const files = Array.from(e.target.files||[]); for (const f of files) await handleUpload(f); renderRoute(); };
  $$('[data-read]').forEach(b => b.onclick = () => readBuiltIn(parseInt(b.dataset.read,10)));
  $$('[data-dl]').forEach(b => b.onclick = () => downloadBuiltIn(parseInt(b.dataset.dl,10)));
  $$('[data-uopen]').forEach(b => b.onclick = () => openUploaded(b.dataset.uopen));
  $$('[data-udl]').forEach(b => b.onclick = () => downloadUploaded(b.dataset.udl));
  $$('[data-udel]').forEach(b => b.onclick = () => {
    const id = b.dataset.udel;
    confirmBox('删除文档？', '该上传文档将从本设备删除。', async () => {
      await idbDel(id);
      S.store.uploadsMeta = S.store.uploadsMeta.filter(u=>u.id!==id);
      S.store.removedUploads[id] = Date.now();
      saveStore(); renderRoute(); toast('已删除');
    }, '删除');
  });
}
async function handleUpload(file){
  const MAX_SYNC = 150000;
  const id = 'u' + Date.now() + Math.random().toString(36).slice(2,7);
  const buf = new Uint8Array(await file.arrayBuffer());
  const rec = { id, name: file.name, type: file.type, size: buf.length, addedAt: Date.now(), blob: new Blob([buf], {type: file.type || 'application/octet-stream'}) };
  await idbPut(rec);
  const meta = { id, name: file.name, type: file.type, size: buf.length, addedAt: Date.now() };
  if (buf.length <= MAX_SYNC) meta.syncData = b64e(buf);
  S.store.uploadsMeta.push(meta);
  saveStore();
  toast(`已上传：${file.name}${meta.syncData?'（将云同步）':'（仅本设备）'}`);
}
async function getBuiltInBytes(idx){
  const d = S.bundle.docs[idx];
  const enc = await fetchJSON(d.file);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d(enc.iv)}, S.contentKey, b64d(enc.data));
  return { bytes: new Uint8Array(pt), name: d.name };
}
async function downloadBuiltIn(idx){
  try {
    toast('解密并准备下载…');
    const { bytes, name } = await getBuiltInBytes(idx);
    const url = URL.createObjectURL(new Blob([bytes], {type:'application/pdf'}));
    const a = document.createElement('a'); a.href = url; a.download = name; a.click();
    setTimeout(()=>URL.revokeObjectURL(url), 4000);
    toast('已开始下载 ✓');
  } catch(e){ toast('下载失败：'+e.message, true); }
}
async function downloadUploaded(id){
  const rec = await idbGet(id); if (!rec) return toast('文件不存在', true);
  const url = URL.createObjectURL(rec.blob);
  const a = document.createElement('a'); a.href = url; a.download = rec.name; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 4000);
}
async function openUploaded(id){
  const rec = await idbGet(id); if (!rec) return toast('文件不存在（可能来自另一台设备，需在本机重新上传）', true);
  const buf = new Uint8Array(await rec.blob.arrayBuffer());
  if (rec.name.toLowerCase().endsWith('.pdf')) return openReader(rec.name, buf);
  if (rec.type && rec.type.startsWith('image/')){
    const url = URL.createObjectURL(rec.blob);
    modal(`<h3 style="font-size:16px;margin-bottom:10px">${esc(rec.name)}</h3><img src="${url}" style="max-width:100%;border-radius:10px">
      <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn btn-ghost btn-sm" onclick="closeModal()">关闭</button></div>`);
    return;
  }
  const text = TD.decode(buf);
  modal(`<h3 style="font-size:16px;margin-bottom:10px">${esc(rec.name)}</h3><pre style="white-space:pre-wrap;font-size:13.5px;background:#f6f7fb;padding:12px;border-radius:10px;max-height:60vh;overflow:auto">${esc(text)}</pre>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn btn-ghost btn-sm" onclick="closeModal()">关闭</button></div>`);
}

/* ================= PDF 阅读器 ================= */
const reader = { pdf:null, page:1, rendering:false, pending:new Set(), observer:null };
async function readBuiltIn(idx){
  try {
    toast('解密文档…');
    const { bytes, name } = await getBuiltInBytes(idx);
    openReader(name, bytes);
  } catch(e){ toast('打开失败：'+e.message, true); }
}
async function openReader(name, bytes){
  if (!window.pdfjsLib){ toast('PDF 组件尚未加载完成，请稍候重试', true); return; }
  pdfjsLib.GlobalWorkerOptions.workerSrc = 'assets/pdf.worker.min.js';
  modal(`<div class="reader-toolbar">
      <span class="doc-title">${esc(name)}</span>
      <button class="btn btn-ghost btn-sm" id="rd-prev">上一页</button>
      <span id="rd-ind" style="font-size:13px;color:var(--sub);white-space:nowrap">-/-</span>
      <button class="btn btn-ghost btn-sm" id="rd-next">下一页</button>
      <button class="btn btn-ghost btn-sm" id="rd-dl">下载</button>
      <button class="btn btn-ghost btn-sm" id="rd-close">关闭</button>
    </div><div class="reader-pages" id="rd-pages"></div>`);
  $('#rd-close').onclick = () => { destroyReader(); closeModal(); };
  $('#rd-dl').onclick = () => { const url = URL.createObjectURL(new Blob([bytes], {type:'application/pdf'})); const a=document.createElement('a'); a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),4000); };
  const indEl = $('#rd-ind'), pagesEl = $('#rd-pages');
  const alive = () => indEl && indEl.isConnected && reader.pdf !== null;
  reader.pdf = null;
  const pdf = await pdfjsLib.getDocument({ data: bytes }).promise;
  if (!alive()) { destroyReader(); return; } // 阅读器已被用户关闭，放弃渲染
  reader.pdf = pdf; reader.page = 1;
  indEl.textContent = `1 / ${pdf.numPages}`;
  const canvases = [];
  for (let i=1;i<=pdf.numPages;i++){
    const holder = document.createElement('div');
    holder.style.minHeight = '120px';
    holder.dataset.page = i;
    pagesEl.appendChild(holder);
    canvases.push(holder);
  }
  const renderPage = async (n) => {
    if (reader.rendering || !alive()) return;
    reader.rendering = true;
    try {
      const holder = canvases[n-1]; if (!holder || holder.dataset.done || !alive()) return;
      const page = await pdf.getPage(n);
      if (!alive()) return;
      const vw = Math.min(pagesEl.clientWidth - 36, 820);
      const base = page.getViewport({ scale: 1 });
      const scale = vw / base.width;
      const viewport = page.getViewport({ scale: scale * Math.min(window.devicePixelRatio||1, 2) });
      const canvas = document.createElement('canvas');
      canvas.width = viewport.width; canvas.height = viewport.height;
      canvas.style.width = (vw) + 'px';
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      if (!alive()) return;
      holder.innerHTML = ''; holder.appendChild(canvas); holder.dataset.done = '1';
      indEl.textContent = `${n} / ${pdf.numPages}`;
    } finally { reader.rendering = false; }
  };
  await renderPage(1);
  if (!alive()) { destroyReader(); return; }
  reader.observer = new IntersectionObserver(entries => {
    for (const en of entries){ if (en.isIntersecting && alive()){ const n = parseInt(en.target.dataset.page,10); renderPage(n); reader.page = n; indEl.textContent = `${n} / ${pdf.numPages}`; } }
  }, { root: pagesEl, rootMargin: '400px' });
  canvases.forEach(h => reader.observer.observe(h));
  $('#rd-prev').onclick = () => scrollToPage(Math.max(1, reader.page - 1));
  $('#rd-next').onclick = () => scrollToPage(Math.min(pdf.numPages, reader.page + 1));
  function scrollToPage(n){ const h = canvases[n-1]; if (h) h.scrollIntoView({behavior:'smooth', block:'start'}); }
}
function destroyReader(){ if (reader.observer){ reader.observer.disconnect(); reader.observer = null; } reader.pdf = null; }

/* ================= 首页 ================= */
function renderHome(root){
  const total = S.bundle.questions.length;
  const doneN = Object.keys(S.store.progress).length;
  const wrongN = S.store.wrong.length;
  const masterN = Object.keys(S.store.mastered).length;
  root.innerHTML = `
    <div class="page-title">你好，${esc(S.user.name)}</div>
    <div class="page-sub">${esc(S.bundle.meta.title)} · 题库来自「${esc(S.bundle.meta.source)}」</div>
    <div class="stats-grid">
      <div class="stat-card"><div class="num">${total}</div><div class="lbl">题库总数</div></div>
      <div class="stat-card accent"><div class="num">${doneN}</div><div class="lbl">已练习</div></div>
      <div class="stat-card warm"><div class="num">${wrongN}</div><div class="lbl">错题本</div></div>
      <div class="stat-card good"><div class="num">${masterN}</div><div class="lbl">已掌握</div></div>
    </div>
    <div class="card">
      <b>快捷入口</b>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:12px">
        <button class="btn btn-primary" data-go="#/recite">开始背题</button>
        <button class="btn btn-ghost" data-go="#/quiz">开始做题</button>
        <button class="btn btn-ghost" data-go="#/wrong">错题本</button>
        <button class="btn btn-ghost" data-go="#/docs">文档中心</button>
      </div>
    </div>
    <div class="card"><b>题型分布</b><div class="type-dist" style="margin-top:10px">${S.bundle.meta.typeOrder.map(t=>{
      const c = S.bundle.questions.filter(q=>q.type===t).length;
      return `<div class="dist-row"><span class="nm">${S.bundle.meta.typeNames[t]}</span><span class="bar"><i style="width:${(c/total*100).toFixed(1)}%"></i></span><span class="ct">${c}</span></div>`;
    }).join('')}</div></div>
    <div class="card" style="font-size:13px;color:var(--sub)">
      <b style="color:var(--ink)">说明</b><br>
      · 题目与挖空完全按老师原卷《${esc(S.bundle.meta.source)}》整理，填空题挖空位置与原卷下划线一致。<br>
      · 简答/分析题为开放题，参考答案部分由 AI 依据课件补充，已标注说明。<br>
      ${S.user.guest ? '· 当前为游客模式，数据仅保存在本设备，不会云同步。' : '· 登录同一账号即可在手机/电脑间同步错题本与练习记录。'}
    </div>`;
  root.querySelectorAll('[data-go]').forEach(b => b.onclick = () => { location.hash = b.dataset.go; });
}

/* ================= 设置 ================= */
function renderSettings(root){
  const lastSync = S.sync.lastOk ? fmtTime(S.sync.lastOk) : '从未';
  root.innerHTML = `
    <div class="page-title">设置</div>
    <div class="page-sub">账号、云同步与偏好</div>
    <div class="card">
      <div class="set-row"><div class="info"><div class="t">当前账号：${esc(S.user.name)}${S.user.guest?'（游客）':''}</div><div class="d">账号信息保存在本机；换设备登录同一账号密码即可取回同步数据。</div></div>
        <button class="btn btn-ghost btn-sm" id="st-logout">退出登录</button></div>
      <div class="set-row"><div class="info"><div class="t">云同步</div><div class="d">最近成功同步：${lastSync}${S.sync.err?` · 上次错误：${esc(S.sync.err)}`:''}<br>数据以你的账号密码加密后保存在云端，服务器无法读取内容。</div></div>
        <button class="btn btn-primary btn-sm" id="st-sync" ${S.user.guest?'disabled':''}>立即同步</button></div>
      <div class="set-row"><div class="info"><div class="t">同步码（离线兜底）</div><div class="d">若云同步不可用，可导出同步码，在另一设备导入恢复数据。</div></div>
        <button class="btn btn-ghost btn-sm" id="st-exp" ${S.user.guest?'disabled':''}>导出</button>
        <button class="btn btn-ghost btn-sm" id="st-imp" ${S.user.guest?'disabled':''}>导入</button></div>
      <div class="set-row"><div class="info"><div class="t">做题答错自动加入错题本</div><div class="d">关闭时，可在每题的结果面板手动点「☆ 加入错题本」。</div></div>
        <label class="switch"><input type="checkbox" id="st-auto" ${S.store.settings.autoWrong?'checked':''}><i></i></label></div>
      <div class="set-row"><div class="info"><div class="t">背题默认遮挡答案</div><div class="d">进入背题模式时默认遮挡，逐题点击查看。</div></div>
        <label class="switch"><input type="checkbox" id="st-mask" ${S.store.settings.maskDefault?'checked':''}><i></i></label></div>
      <div class="set-row"><div class="info"><div class="t">重置练习进度</div><div class="d">清空做题记录与已掌握标记（不影响错题本）。</div></div>
        <button class="btn btn-danger btn-sm" id="st-reset">重置</button></div>
    </div>
    <div class="card" style="font-size:12.5px;color:var(--sub)">
      逆向工程复习站 · 题库：${esc(S.bundle.meta.source)} · 共 ${S.bundle.questions.length} 题<br>
      全站内容（题库与文档）以 AES-256-GCM 加密存放，访问密码不存储于任何服务器。
    </div>`;
  $('#st-logout').onclick = () => { sessionStorage.removeItem('rr_sess'); S.user = null; S.store = null; location.hash = ''; showLogin(); };
  $('#st-sync').onclick = () => doSync(true);
  $('#st-exp').onclick = exportSyncCode;
  $('#st-imp').onclick = importSyncCode;
  $('#st-auto').onchange = e => { S.store.settings.autoWrong = e.target.checked; saveStore(); toast('已保存'); };
  $('#st-mask').onchange = e => { S.store.settings.maskDefault = e.target.checked; S.reciteMasked = e.target.checked; S.reciteRevealed.clear(); saveStore(); toast('已保存'); };
  $('#st-reset').onclick = () => confirmBox('重置练习进度？','将清空做题记录与已掌握标记。', () => { S.store.progress = {}; S.store.mastered = {}; saveStore(); renderRoute(); toast('已重置'); });
}

/* ================= 路由 ================= */
const routes = { home: renderHome, recite: renderRecite, quiz: renderQuiz, wrong: renderWrong, docs: renderDocs, settings: renderSettings };
function currentRoute(){ const h = location.hash.replace(/^#\//,''); return routes[h] ? h : 'home'; }
function renderRoute(){
  if (!S.bundle) return;
  const view = currentRoute();
  S.view = view;
  $$('#mainnav a').forEach(a => a.classList.toggle('active', a.dataset.route === view));
  $$('#tabbar a').forEach(a => a.classList.toggle('active', a.dataset.route === view));
  $('#whoami').textContent = S.user ? S.user.name : '';
  routes[view]($('#view'));
}
window.addEventListener('hashchange', () => { if (S.bundle && S.user) renderRoute(); });

/* ================= 启动流程 ================= */
function showGate(){ $('#gate').classList.remove('hidden'); $('#app').classList.add('hidden'); $('#login').classList.add('hidden'); }
function showLogin(){ $('#login').classList.remove('hidden'); $('#app').classList.add('hidden'); const last = localStorage.getItem('rr_lastUser')||''; $('#login-user').value = last; }
function showApp(){
  $('#gate').classList.add('hidden'); $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  renderRoute();
  if (S.sync.lastOk) setSyncBadge('ok','已同步 '+fmtTime(S.sync.lastOk)); else setSyncBadge('', '·');
}
async function enterApp(){
  try { const sess = JSON.parse(sessionStorage.getItem('rr_sess')||'null');
    if (sess){ if (sess.syncKeyB64) sess.syncKeyU8 = b64d(sess.syncKeyB64);
      S.user = sess; S.store = loadStore(sess.name); } } catch(e){}
  if (!S.user) { showLogin(); return; }
  showApp();
  if (!S.user.guest) doSync(false);
}
async function boot(){
  // 1) 恢复内容解锁
  let unlocked = await resumeUnlock();
  if (!unlocked){ showGate(); return; }
  // 2) 恢复会话
  await enterApp();
}
/* 密码门提交 */
$('#gate-form').addEventListener('submit', async e => {
  e.preventDefault();
  const pw = $('#gate-pw').value;
  if (!pw) return;
  const btn = $('#gate-btn'); btn.disabled = true; btn.textContent = '解密中…';
  try {
    await unlockFlow(pw);
    btn.textContent = '✓ 解锁成功';
    await enterApp();
  } catch(err){
    const card = $('.gate-card'); card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
    $('#gate-err').textContent = '密码不正确，或内容解密失败';
    btn.disabled = false; btn.textContent = '解锁内容';
  }
});
$('#gate-eye').onclick = () => { const i = $('#gate-pw'); i.type = i.type === 'password' ? 'text' : 'password'; $('#gate-eye').textContent = i.type === 'password' ? '显示' : '隐藏'; };
/* 登录提交 */
$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const name = $('#login-user').value.trim();
  const pw = $('#login-pw').value;
  const err = $('#login-err');
  if (!name){ err.textContent = '请输入账号'; return; }
  if (!pw || pw.length < 4){ err.textContent = '密码至少4位'; return; }
  const btn = $('#login-btn'); btn.disabled = true; btn.textContent = '登录中…';
  try {
    const has = !!loadProfiles()[name];
    if (!has && !confirm(`账号「${name}」不存在，将以此账号密码新建档案并开始云同步。继续？`)) { btn.disabled=false; btn.textContent='登录 / 首次使用自动创建'; return; }
    S.user = await loginAccount(name, pw, true);
    S.store = loadStore(name);
    localStorage.setItem('rr_lastUser', name);
    sessionStorage.setItem('rr_sess', JSON.stringify({name:S.user.name, guest:false, syncKeyB64:S.user.syncKeyB64}));
    btn.textContent = '✓ 登录成功';
    showApp();
    doSync(false);
  } catch(e2){
    err.textContent = e2.message || '登录失败';
    btn.disabled = false; btn.textContent = '登录 / 首次使用自动创建';
  }
});
$('#login-eye').onclick = () => { const i = $('#login-pw'); i.type = i.type === 'password' ? 'text' : 'password'; $('#login-eye').textContent = i.type === 'password' ? '显示' : '隐藏'; };
$('#guest-btn').onclick = () => {
  S.user = { name:'游客', syncKeyU8:null, guest:true };
  S.store = loadStore('guest');
  sessionStorage.removeItem('rr_sess');
  showApp();
};
/* 页面隐藏时尽力推送同步 */
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden' && S.user && !S.user.guest) doSync(false); });
boot();
