"use strict";
// RAKSHA operator console — all rendering, no external dependency. Served from /app.js by
// console/server.py. Every value shown comes from /api/snapshot or a per-finding endpoint; this file
// computes no security fact of its own.
const $ = (s, r=document) => r.querySelector(s);
const el = (tag, cls, txt) => { const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; };
const TOKEN = (document.querySelector('meta[name="raksha-token"]')||{}).content || "";
let STATE = null, SELECTED = null, LABELS = {}, LANG = "en";

const SCREENS = [
  ["board","Mission Board"],["pipeline","Live Pipeline"],["events","Event Log"],
  ["detail","Finding Detail"],["graph","Attack Graph"],["estate","Estate Map"],
  ["pqc","Post-Quantum"],["vault","Evidence Vault"],["score","Scorecard"],["brief","Commander's Brief"],
];

function buildTabs(){
  const nav = $("nav.tabs");
  SCREENS.forEach(([id,label],i)=>{
    const b = el("button", null, (i+1)+" · "+label);
    b.setAttribute("role","tab"); b.setAttribute("aria-selected", i===0); b.dataset.screen=id; b.dataset.label=label;
    b.addEventListener("click", ()=>showScreen(id));
    nav.appendChild(b);
  });
}
function showScreen(id){
  document.querySelectorAll("nav.tabs button").forEach(b=>b.setAttribute("aria-selected", b.dataset.screen===id));
  SCREENS.forEach(([s])=>$("#"+s).hidden = (s!==id));
}

// ---- i18n (F10): swap data-i18n labels and tab labels from the Hindi glossary
function applyLang(){
  const on = LANG==="hi";
  document.querySelectorAll("nav.tabs button").forEach(b=>{
    const base = b.textContent.replace(/^\d+ · /,""); const num = b.textContent.match(/^\d+/)[0];
    b.textContent = num+" · "+(on && LABELS[b.dataset.label] || b.dataset.label);
  });
  document.querySelectorAll("[data-i18n]").forEach(e=>{
    const k=e.getAttribute("data-i18n"); if(on && LABELS[k]) e.textContent=LABELS[k];
  });
  $("#t-lang").textContent = on ? "हि" : "EN"; $("#t-lang").setAttribute("aria-pressed", on);
  if(SELECTED) showBriefIfActive();
}

// ---- data
async function refresh(){
  try{
    const r = await fetch("/api/snapshot"); STATE = await r.json();
    renderBadges(); renderBoard(); populateFilters(); renderList(); renderPipeline(); renderRisk();
    renderEvents(); renderGraph(); renderEstate(); renderPqc(); renderVaultList(); renderScore(); renderBriefList();
    $("#foot-count").textContent = STATE.findings.length+" findings · "+STATE.board.length+" targets";
    $("#foot-time").textContent = "updated "+new Date().toLocaleTimeString();
  }catch(e){ $("#foot-time").textContent = "offline"; }
}

function renderBadges(){
  const p = STATE.scorecard.precision.reports_with_reproducer_pct;
  $("#b-prec").textContent = (p==null?"—":p+"%");
  const post = STATE.scorecard.posture;
  for(const [id,v] of [["#b-net",post.network_interfaces],["#b-cloud",post.cloud_calls]]){
    $(id).textContent = v; $(id).classList.toggle("warn", v!==0);
  }
}

function renderBoard(){
  const g = $("#board-grid"); g.textContent="";
  for(const t of STATE.board){
    const c = el("div","card "+t.build_status);
    c.appendChild(el("h3", null, t.name));
    c.appendChild(el("div","langs",(t.languages.join(" · ")||"—")));
    const bs = el("div","row"); bs.appendChild(el("span","k","build"));
    bs.appendChild(el("span","pill "+t.build_status,
      t.build_status==="green"?"built":t.build_status==="amber"?"build-free · finding":"could not ingest"));
    c.appendChild(bs);
    addRow(c,"findings", t.findings+(t.verified?(" · "+t.verified+" fixed"):""));
    addRow(c,"ROE", t.roe_level); addRow(c,"status", t.status);
    if(t.note) c.appendChild(el("div","note", t.note));
    g.appendChild(c);
  }
}
function addRow(card,k,v){ const r=el("div","row"); r.appendChild(el("span","k",k)); r.appendChild(el("span","v",String(v))); card.appendChild(r); }

function renderPipeline(){
  const flow = $("#pipe-flow"); if(!STATE.pipeline) return; flow.textContent="";
  STATE.pipeline.forEach(st=>{
    const d = el("div","stage"+(st.count?" on":""));
    d.appendChild(el("div","n", String(st.at_or_past!=null?st.at_or_past:st.count)));
    d.appendChild(el("div","s", st.status.replace(/_/g," ")));
    flow.appendChild(d);
  });
}
function renderRisk(){
  const list = $("#risk-list"); if(!STATE.risk) return; list.textContent="";
  STATE.risk.slice(0,12).forEach((r,i)=>{
    const row = el("div","frow"); row.appendChild(el("span","sev "+r.severity));
    const b = el("div","fmsg");
    b.appendChild(el("div",null,"#"+(i+1)+"  "+(r.message||r.bug_class)));
    b.appendChild(el("div","fmeta","score "+r.score+" · "+r.language+" · "+r.status+(r.has_fix?" · fix ready":"")));
    row.appendChild(b); row.addEventListener("click",()=>selectFinding(r.id)); list.appendChild(row);
  });
}

// ---- F1 event log
function renderEvents(){
  const log = $("#event-log"); if(!STATE.events){ return; } log.textContent="";
  if(!STATE.events.length){ log.appendChild(el("div","ev dim", "no events yet")); return; }
  STATE.events.forEach(ev=>{
    const row = el("div","ev "+(ev.level||"info"));
    row.appendChild(el("span","dot"));
    row.appendChild(el("span","t", (ev.at||"").slice(11,19)));
    const txt = el("span","x"); txt.textContent = "#"+ev.seq+"  "+ev.text; row.appendChild(txt);
    log.appendChild(row);
  });
}

// ---- F8 search + filter + sort over the finding list
function populateFilters(){
  const vals = (key)=>[...new Set(STATE.findings.map(f=>f[key]).filter(Boolean))].sort();
  fillSelect("#f-lang","all languages", vals("language"));
  fillSelect("#f-status","all status", vals("status"));
  fillSelect("#f-sev","all severity", vals("severity"));
  fillSelect("#f-lane","all lanes", [...new Set(STATE.findings.map(f=>(f.oracle||"").split(":")[0]).filter(Boolean))].sort());
}
function fillSelect(sel,allLabel,opts){
  const s=$(sel); const cur=s.value; s.textContent="";
  s.appendChild(new Option(allLabel,""));
  opts.forEach(o=>s.appendChild(new Option(o,o)));
  if(opts.includes(cur)) s.value=cur;
}
function filteredFindings(){
  const q=($("#search").value||"").toLowerCase();
  const lang=$("#f-lang").value, st=$("#f-status").value, sev=$("#f-sev").value, lane=$("#f-lane").value, sort=$("#f-sort").value;
  let rows = STATE.findings.filter(f=>{
    if(lang && f.language!==lang) return false;
    if(st && f.status!==st) return false;
    if(sev && f.severity!==sev) return false;
    if(lane && (f.oracle||"").split(":")[0]!==lane) return false;
    if(q && !((f.message||"")+" "+(f.bug_class||"")+" "+(f.target||"")).toLowerCase().includes(q)) return false;
    return true;
  });
  const sevOrder={critical:0,high:1,medium:2,low:3,info:4};
  const cmp={sev:(a,b)=>(sevOrder[a.severity]??9)-(sevOrder[b.severity]??9)||a.language.localeCompare(b.language),
             lang:(a,b)=>a.language.localeCompare(b.language),
             status:(a,b)=>a.status.localeCompare(b.status)}[sort]||(()=>0);
  return rows.sort(cmp);
}
function renderList(){
  const list = $("#flist"); if(!list) return; list.textContent="";
  const rows = filteredFindings();
  if(!rows.length){ list.appendChild(el("div","frow", "no findings match")); return; }
  for(const f of rows){
    const row = el("div","frow"); row.dataset.id=f.id; row.setAttribute("aria-selected", f.id===SELECTED);
    row.appendChild(el("span","sev "+f.severity));
    const body = el("div","fmsg");
    body.appendChild(el("div",null, f.message.length>70?f.message.slice(0,70)+"…":f.message));
    body.appendChild(el("div","fmeta", f.language+" · "+f.bug_class+" · "+f.status+(f.evidence?(" · "+f.evidence):"")));
    if(f.disputed) body.appendChild(el("div","disp","⚑ disputed by operator"));
    row.appendChild(body);
    row.addEventListener("click", ()=>selectFinding(f.id));
    list.appendChild(row);
  }
}
["#search","#f-lang","#f-status","#f-sev","#f-lane","#f-sort"].forEach(sel=>{
  document.addEventListener("input", e=>{ if(e.target.matches(sel)) renderList(); });
});

// ---- F3/F4/F7/F13/F14: finding detail
async function selectFinding(id){
  SELECTED = id; renderList(); showScreen("detail");
  const r = await fetch("/api/finding/"+encodeURIComponent(id));
  if(!r.ok){ $("#fdetail").innerHTML='<p class="empty">not found</p>'; return; }
  renderDetail(await r.json());
}
function tick(s){ return s==="pass"?"✓":s==="fail"?"✗":"·"; }
function laneTrustFor(oracle){
  const lane=(oracle||"").split(":")[0]; const lt=(STATE.lane_trust||{})[lane];
  if(!lt) return null;
  return lane+" lane on this estate: "+lt.findings+" finding(s), "+lt.proven+" proven"+(lt.disputed?(", "+lt.disputed+" disputed"):"");
}
function renderDetail(p){
  const d = $("#fdetail"); d.textContent="";
  if(p.disputed){ const w=el("div","banner"); w.appendChild(el("b",null,"Operator marked this a false positive: ")); w.appendChild(document.createTextNode(p.disputed)); d.appendChild(w); }
  d.appendChild(el("h3", null, p.bug_class+" — "+p.severity.toUpperCase()));
  d.appendChild(el("div","meta", p.language+" · "+p.target+" · "+p.oracle+" · "+p.status));
  const lt = laneTrustFor(p.oracle); if(lt) d.appendChild(el("div","evidence","⚖ "+lt));

  // F13 two voices
  const vc = el("div","voices");
  const vStaff = el("button","ctl","Staff view"), vEng=el("button","ctl","Engineer view");
  vStaff.setAttribute("aria-pressed","true");
  vc.appendChild(vStaff); vc.appendChild(vEng); d.appendChild(vc);
  const voiceBox = el("div"); d.appendChild(voiceBox);
  vEng.addEventListener("click",()=>{vEng.setAttribute("aria-pressed","true");vStaff.setAttribute("aria-pressed","false");renderEngineer(voiceBox,p);});
  vStaff.addEventListener("click",()=>{vStaff.setAttribute("aria-pressed","true");vEng.setAttribute("aria-pressed","false");renderStaff(voiceBox,p);});
  renderStaff(voiceBox, p);

  // F7 operator actions
  const acts = el("div","actions");
  const mk=(label,cls,fn,enabled)=>{const b=el("button","act"+(cls?" "+cls:""),label); b.disabled=!enabled; b.addEventListener("click",fn); acts.appendChild(b);};
  const verified = p.status==="VERIFIED";
  mk("Approve","ok", ()=>doAction("approve",p.id,"Approve this proven fix for deployment?"), verified);
  mk("Reject","bad", ()=>doAction("reject",p.id,"Reason for rejecting this fix:",true), verified);
  mk("Mark false positive",null, ()=>doAction("false_positive",p.id,"Why is this a false positive?",true), true);
  mk("Re-run red team",null, ()=>doAction("rerun_red_team",p.id,null), verified);
  mk("Export bundle",null, ()=>doAction("export",p.id,null), p.status!=="SUSPECTED");
  d.appendChild(acts);
  const alog = el("div","actlog"); alog.id="actlog";
  if(p.operator_actions && p.operator_actions.length)
    alog.textContent = "actions: "+p.operator_actions.map(a=>a.action+" by "+a.actor).join(" · ");
  d.appendChild(alog);
}
function renderStaff(box,p){
  box.textContent="";
  fetch("/api/voices/"+encodeURIComponent(p.id)).then(r=>r.ok?r.json():null).then(v=>{
    if(!v){ box.appendChild(el("p","empty","—")); return; } const s=v.staff;
    box.appendChild(el("p",null,s.summary));
    const a=el("p",null); a.appendChild(el("b",null,"Action: ")); a.appendChild(document.createTextNode(s.action)); box.appendChild(a);
    if(s.cvss31!=null) box.appendChild(el("div","evidence","derived CVSS 3.1: "+s.cvss31));
  });
}
function renderEngineer(box,p){
  box.textContent="";
  // F3 split-screen replay: vulnerable fires vs patched dead
  const rep = el("div","replay");
  const before=p.replay_before, after=p.replay_after, repro=p.reproducer;
  const v=el("div","pane vuln"); v.appendChild(el("div","lab","vulnerable build"));
  v.appendChild(el("div","big", before && before.oracle_fired ? "attack fires ✗" : "attack fires"));
  if(repro) v.appendChild(el("div","mono","input "+(repro.size_bytes||"?")+" bytes · "+(repro.kind||"")));
  rep.appendChild(v);
  const fx=el("div","pane fixed"); fx.appendChild(el("div","lab","patched build"));
  fx.appendChild(el("div","big", after ? (after.oracle_fired?"still fires ✗":"attack dead ✓") : "not yet patched"));
  if(after&&after.sig) fx.appendChild(el("div","mono","signature silent"));
  rep.appendChild(fx); box.appendChild(rep);

  // F4 gate strip incl. twin + bound proof + reachability
  const gate = el("div","gate");
  ["COMPILES","POV_DEAD","DIFFERENTIAL_CORPUS","COVERAGE_HELD","CLEAN_REFUZZ"].forEach(c=>{
    const res=p.gate?p.gate[c]:null; const st=res==null?"pend":(res.passed?"pass":"fail");
    const g=el("div","g"); g.appendChild(el("span","tick "+st, tick(st)));
    g.appendChild(el("span",null,c.replace(/_/g," ").toLowerCase()));
    if(res&&res.detail) g.appendChild(el("span","gd", res.detail.length>52?res.detail.slice(0,52)+"…":res.detail));
    gate.appendChild(g);
  });
  const extra=(lab,rec)=>{ if(!rec||!rec.status) return;
    const ok=["proved","unreachable"].includes(rec.status); const bad=["refuted","reachable"].includes(rec.status);
    const g=el("div","g"); g.appendChild(el("span","tick "+(ok?"pass":bad?"fail":"pend"), ok?"✓":bad?"✗":"·"));
    g.appendChild(el("span",null,lab)); g.appendChild(el("span","gd", (rec.after?rec.after.status:rec.status))); gate.appendChild(g);
  };
  extra("solver: bad index unreachable", p.reach_proof);
  extra("solver: clamp arithmetic", p.bound_proof);
  box.appendChild(gate);

  if(repro) box.appendChild(el("div","evidence","evidence: "+repro.kind+(repro.detail?(" — "+repro.detail):"")));
  if(p.fix_site_set && p.fix_site_set.length){ const s=p.fix_site_set[0];
    box.appendChild(el("div","evidence","fix site: "+s.uri+(s.start_line?(":"+s.start_line):"")+(s.rationale?(" — "+s.rationale):""))); }

  if(p.frontier && p.frontier.length){
    box.appendChild(el("div","lab","repair frontier — candidates that passed the gate"));
    const rr=el("div","rounds");
    p.frontier.forEach((c,i)=>{const parts=["#"+(i+1)+" "+c.lane, c.hunks+" hunk(s)", "+"+c.added_lines+"/-"+c.removed_lines];
      if(c.perf_delta!=null) parts.push("perf "+Number(c.perf_delta).toFixed(2)+"x");
      if(c.chosen) parts.push("← chosen");
      rr.appendChild(el("div","r"+(c.chosen?" chosen":""), parts.join(" · ")));});
    box.appendChild(rr);
  }
  if(p.red_team){ const rt=p.red_team;
    box.appendChild(el("div","evidence","independent red team: "+(rt.held?"held — no input broke the fix":(rt.wins+" input(s) broke the fix"))+
      " ("+rt.attempts+" attempts)")); }
  if(p.patch_diff){
    box.appendChild(el("div","lab", p.status==="VERIFIED"?"proven patch":"candidate patch (not proven)"));
    const pre=el("pre","diff");
    p.patch_diff.split("\n").forEach(line=>{
      const cls=line.startsWith("+")&&!line.startsWith("+++")?"add":line.startsWith("-")&&!line.startsWith("---")?"del":"";
      pre.appendChild(el("span",cls,line+"\n")); });
    box.appendChild(pre);
  }
}
async function doAction(action, id, prompt_, needReason){
  let reason=null;
  if(prompt_){ reason=window.prompt(prompt_); if(needReason && !(reason&&reason.trim())) return; if(reason===null && needReason) return; }
  const r = await fetch("/api/action/"+action, {method:"POST", headers:{"Content-Type":"application/json","X-RAKSHA-Token":TOKEN},
    body: JSON.stringify({finding:id, actor:"operator", reason:reason})});
  const res = await r.json();
  $("#actlog").textContent = res.ok ? ("✓ "+action+" recorded"+(res.held!=null?(" — red team "+(res.held?"held":"broke")):"")) : ("✗ "+(res.error||"failed"));
  await refresh();
  if(SELECTED){ const d=await fetch("/api/finding/"+encodeURIComponent(SELECTED)); if(d.ok) renderDetail(await d.json()); }
}

// ---- F2 attack graph (inline SVG, cheapest path lit, edges hover their rule)
function renderGraph(){
  const host=$("#ag"), legend=$("#ag-legend"); if(!host) return; host.textContent=""; legend.textContent="";
  const g=STATE.attack_graph; if(!g || !g.nodes.length){ host.appendChild(el("p","empty","no multi-step chains on this estate")); return; }
  const cheapest = g.summary && g.summary.cheapest_path ? new Set(g.summary.cheapest_path.steps.map(s=>s)) : new Set();
  // lay nodes in columns by capability tier
  const cols=["info-leak","weak-crypto","memory","credential","unauth-endpoint","rce","authz","ssrf"];
  const colOf=n=>Math.max(0, cols.indexOf(n.capability));
  const byCol={}; g.nodes.forEach(n=>{(byCol[colOf(n)]=byCol[colOf(n)]||[]).push(n);});
  const CW=200, RH=54, pad=16; const maxRows=Math.max(1,...Object.values(byCol).map(a=>a.length));
  const ncols=Math.max(...g.nodes.map(colOf))+1;
  const W=ncols*CW+pad*2, H=maxRows*RH+pad*2;
  const pos={};
  Object.entries(byCol).forEach(([c,arr])=>arr.forEach((n,i)=>{pos[n.finding_id]={x:pad+(+c)*CW+10,y:pad+i*RH+10};}));
  const svgNS="http://www.w3.org/2000/svg";
  const svg=document.createElementNS(svgNS,"svg"); svg.setAttribute("viewBox",`0 0 ${W} ${H}`); svg.setAttribute("role","img");
  const litFindingIds=new Set();
  if(g.summary&&g.summary.cheapest_path) (g.chains.find(c=>c.id===g.summary.cheapest_path.id)||{finding_ids:[]}).finding_ids.forEach(i=>litFindingIds.add(i));
  (g.edges||[]).forEach(e=>{
    const a=pos[e.src], b=pos[e.dst]; if(!a||!b) return;
    const lit = litFindingIds.has(e.src) && litFindingIds.has(e.dst);
    const path=document.createElementNS(svgNS,"path");
    const x1=a.x+170,y1=a.y+20,x2=b.x,y2=b.y+20;
    path.setAttribute("d",`M${x1},${y1} C${x1+40},${y1} ${x2-40},${y2} ${x2},${y2}`);
    path.setAttribute("class","edge"+(lit?" lit":""));
    path.addEventListener("mousemove",ev=>showTip(ev, e.rule+"  (heuristic)"));
    path.addEventListener("mouseleave",hideTip);
    svg.appendChild(path);
  });
  g.nodes.forEach(n=>{
    const p=pos[n.finding_id]; const grp=document.createElementNS(svgNS,"g");
    grp.setAttribute("class","node"+(n.severity==="critical"?" crit":"")); grp.setAttribute("transform",`translate(${p.x},${p.y})`);
    const rect=document.createElementNS(svgNS,"rect"); rect.setAttribute("width","170"); rect.setAttribute("height","40"); rect.setAttribute("rx","4");
    if(litFindingIds.has(n.finding_id)) rect.setAttribute("stroke","var(--amber)"), rect.setAttribute("stroke-width","2.4");
    grp.appendChild(rect);
    const t1=document.createElementNS(svgNS,"text"); t1.setAttribute("x","8"); t1.setAttribute("y","17"); t1.textContent=n.capability; grp.appendChild(t1);
    const t2=document.createElementNS(svgNS,"text"); t2.setAttribute("class","cwe"); t2.setAttribute("x","8"); t2.setAttribute("y","31"); t2.textContent=n.cwe+" · "+n.service; grp.appendChild(t2);
    grp.addEventListener("mousemove",ev=>showTip(ev, n.cwe+" at "+n.target+"  (cost "+n.cost+")"));
    grp.addEventListener("mouseleave",hideTip);
    svg.appendChild(grp);
  });
  host.appendChild(svg);
  const s=g.summary||{};
  legend.textContent = (s.viable_chains||0)+" viable chain(s) of "+(s.chains||0)+" · cheapest path lit (cost "+
    (s.cheapest_path?s.cheapest_path.cost:"—")+", budget "+(s.budget||"—")+") · edges labelled with their rule, all heuristic";
}
function showTip(ev,text){ const t=$("#ag-tip"); t.textContent=text; t.style.display="block"; t.style.left=(ev.clientX+12)+"px"; t.style.top=(ev.clientY+12)+"px"; }
function hideTip(){ $("#ag-tip").style.display="none"; }

// ---- F9 estate map
function renderEstate(){
  const host=$("#tiers"), top=$("#top3"); if(!host) return; host.textContent=""; top.textContent="";
  const em=STATE.estate_map; if(!em){ return; }
  em.tiers.forEach(t=>{
    const d=el("div","tier "+t.tier);
    const th=el("div","th"); th.appendChild(el("span","tt", t.tier));
    th.appendChild(el("span","fmeta", t.verified+" fixed · "+t.reportable+" proven · "+t.findings+" findings"));
    d.appendChild(th);
    const cells=el("div","cells"); t.targets.forEach(n=>cells.appendChild(el("span","tgt",n))); d.appendChild(cells);
    host.appendChild(d);
  });
  (em.top_risks||[]).forEach((r,i)=>{
    const row=el("div","r"); row.appendChild(el("span","sev "+r.severity)); row.style.alignItems="baseline";
    row.appendChild(el("span",null,"#"+(i+1)+"  "+(r.message||"")+"  (score "+r.score+")"));
    row.addEventListener("click",()=>selectFinding(r.id)); row.style.cursor="pointer"; top.appendChild(row);
  });
}

// ---- F6 post-quantum
function renderPqc(){
  const sum=$("#pqc-sum"), body=$("#pqc-body"); if(!sum) return; sum.textContent=""; body.textContent="";
  const q=STATE.pqc; if(!q){ return; }
  const chip=(n,l)=>{const k=el("div","kpi"); k.appendChild(el("div","n",String(n==null?"—":n))); k.appendChild(el("div","l",l)); sum.appendChild(k);};
  chip(q.sites,"crypto sites"); chip(q.quantum_vulnerable_sites,"quantum-vulnerable"); chip(q.weakened_sites,"already weak");
  chip(q.files_affected,"files affected"); chip(q.blast_radius,"blast radius");
  Object.entries(q.migrations||{}).forEach(([file,rows])=>rows.forEach(m=>{
    const tr=el("tr");
    tr.appendChild(el("td",null,file)); tr.appendChild(el("td",null,String(m.line)));
    tr.appendChild(el("td","prim",m.primitive)); tr.appendChild(el("td",null,m.migration));
    body.appendChild(tr);
  }));
}

// ---- vault
function reportable(){ return STATE.findings.filter(f=>f.status!=="SUSPECTED"); }
function renderVaultList(){
  const list=$("#vault-list"); if(!list) return; list.textContent="";
  reportable().forEach(f=>{
    const row=el("div","frow"); row.appendChild(el("span","sev "+f.severity));
    const b=el("div","fmsg"); b.appendChild(el("div",null,f.bug_class+" · "+f.status));
    b.appendChild(el("div","fmeta", f.target+" · "+(f.evidence||""))); row.appendChild(b);
    const btn=el("button","verify-btn","Verify"); btn.style.alignSelf="center";
    btn.addEventListener("click",e=>{e.stopPropagation(); verifyBundle(f.id);}); row.appendChild(btn); list.appendChild(row);
  });
}
async function verifyBundle(id){
  const box=$("#vault-result"); box.innerHTML='<p class="empty">verifying…</p>';
  const r=await fetch("/api/verify/"+encodeURIComponent(id)); if(!r.ok){ box.innerHTML='<p class="empty">not reportable</p>'; return; }
  const v=await r.json(); box.textContent="";
  box.appendChild(el("div", v.ok?"verify-ok":"verify-bad", v.ok?"✓ SIGNATURE VALID":"✗ VERIFICATION FAILED"));
  box.appendChild(el("div","evidence", v.summary));
}

// ---- scorecard, F5 boundary bars, F14 lane trust
function renderScore(){
  const s=STATE.scorecard, body=$("#score-body"); if(!body) return; body.textContent="";
  const kpis=el("div","kpis");
  const add=(n,l,cls)=>{const k=el("div","kpi "+(cls||"")); k.appendChild(el("div","n",n==null?"—":String(n))); k.appendChild(el("div","l",l)); kpis.appendChild(k);};
  add((s.precision.reports_with_reproducer_pct==null?"—":s.precision.reports_with_reproducer_pct+"%"),"reports with a replaying reproducer","hl");
  add(s.performance.findings_reported,"proven findings reported");
  add(s.performance.bugs_verified_fixed,"verified fixed");
  add(s.scalability.language_count,"languages covered","vi");
  add((s.resource.zero_inference_fix_pct==null?"—":s.resource.zero_inference_fix_pct+"%"),"fixes at zero inference","vi");
  add(s.functionality.zero_human_input_verified,"fixes with zero human input");
  add((s.speed.time_to_first_proven_finding_seconds==null?"—":s.speed.time_to_first_proven_finding_seconds+"s"),"time to first proven finding","hl");
  body.appendChild(kpis);

  // F5 boundary as bars
  const b=s.boundary||{};
  const bars=el("div","bars"); bars.appendChild(el("h2",null,"Assurance boundary"));
  const langExploit=(b.languages_exercised_by_exploit||[]).length, langBF=(b.languages_build_free_only||[]).length;
  stackedBar(bars,"languages: exploit-level vs build-free only",[["exploit",langExploit,langExploit+" exploit"],["buildfree",langBF,langBF+" build-free"]]);
  const built=(b.targets_total||0)-(b.targets_degraded_to_build_free||0);
  stackedBar(bars,"targets: built vs degraded to build-free",[["built",built,built+" built"],["degraded",b.targets_degraded_to_build_free||0,(b.targets_degraded_to_build_free||0)+" degraded"]]);
  const rep=s.performance.findings_reported||0, susp=b.unresolved_suspected||0;
  stackedBar(bars,"findings: reported vs suspected",[["reported",rep,rep+" reported"],["suspected",susp,susp+" suspected"]]);
  body.appendChild(bars);

  // zero badges
  const zero=el("div","zero");
  const z=(n,l)=>{const bd=el("div","zerobadge"+(n!==0?" warn":"")); bd.appendChild(el("div","n",String(n))); bd.appendChild(el("div","l",l)); zero.appendChild(bd);};
  z(s.posture.network_interfaces,"network interfaces"); z(s.posture.cloud_calls,"cloud calls");
  body.appendChild(zero);

  // F14 lane trust line
  const lt=STATE.lane_trust||{};
  if(Object.keys(lt).length){
    const box=el("div","lanetrust"); box.appendChild(el("b",null,"Lane trust on this estate: "));
    Object.values(lt).forEach(r=>box.appendChild(el("span",null, r.lane+" "+r.proven+"/"+r.findings+(r.disputed?(" ("+r.disputed+" disputed)"):""))));
    body.appendChild(box);
  }
  // the boundary statement, verbatim
  const bd=el("div","boundary"); bd.appendChild(el("h3",null,"What this run does not claim"));
  bd.appendChild(el("p",null, b.statement||"—")); body.appendChild(bd);
}
function stackedBar(host,label,segs){
  const total=segs.reduce((a,[,n])=>a+n,0)||1;
  const bar=el("div","bar"); const bl=el("div","bl"); bl.appendChild(el("span",null,label));
  bl.appendChild(el("span",null,segs.map(([,n])=>n).join(" / "))); bar.appendChild(bl);
  const track=el("div","track");
  segs.forEach(([cls,n,title])=>{ if(n<=0) return; const seg=el("div","seg "+cls); seg.style.width=(100*n/total)+"%"; seg.title=title; track.appendChild(seg); });
  bar.appendChild(track); host.appendChild(bar);
}

// ---- F10 brief (bilingual) + F12 PDF
function renderBriefList(){
  const list=$("#brief-list"); if(!list) return; list.textContent="";
  reportable().forEach(f=>{
    const row=el("div","frow"); row.appendChild(el("span","sev "+f.severity));
    const b=el("div","fmsg"); b.appendChild(el("div",null,f.bug_class)); b.appendChild(el("div","fmeta",f.target+" · "+f.status));
    row.appendChild(b); row.addEventListener("click",()=>showBrief(f.id)); list.appendChild(row);
  });
}
let BRIEF_ID=null;
async function showBrief(id){
  BRIEF_ID=id; const body=$("#brief-body"); body.innerHTML='<p class="empty">loading…</p>';
  const r=await fetch("/api/brief/"+encodeURIComponent(id)); if(!r.ok){ body.innerHTML='<p class="empty">not reportable</p>'; $("#brief-pdf").disabled=true; return; }
  const d=await r.json(); body._data=d; $("#brief-pdf").disabled=false; renderBriefBody();
}
function renderBriefBody(){
  const body=$("#brief-body"), d=body._data; if(!d) return; body.textContent="";
  const side = LANG==="hi" ? d.hi : d.en;
  body.appendChild(el("p", null, side.plain));
  body.appendChild(el("pre","brief", side.jssd));
}
function showBriefIfActive(){ if(!$("#brief").hidden && $("#brief-body")._data) renderBriefBody(); }
$("#brief-pdf").addEventListener("click",()=>{ if(BRIEF_ID) window.location="/api/export/brief/"+encodeURIComponent(BRIEF_ID)+".pdf"; });

// ---- F11 contrast, F10 lang, F12 help, keyboard
$("#t-contrast").addEventListener("click",e=>{
  const on = document.documentElement.getAttribute("data-theme")!=="contrast";
  document.documentElement.setAttribute("data-theme", on?"contrast":"");
  e.currentTarget.setAttribute("aria-pressed", on);
});
$("#t-lang").addEventListener("click",()=>{ LANG = LANG==="en"?"hi":"en"; applyLang(); });
async function loadLabels(){ try{ LABELS=await (await fetch("/api/labels")).json(); }catch(e){ LABELS={}; } }
async function buildHelp(){
  try{ const h=await (await fetch("/api/help")).json(); const box=$("#help-rows"); box.textContent="";
    (h.shortcuts||[]).forEach(s=>{const r=el("div","hr"); const k=el("kbd",null,s.keys); r.appendChild(k); r.appendChild(el("span",null,s.action)); box.appendChild(r);});
  }catch(e){}
}
$("#t-help").addEventListener("click",()=>{ $("#help").style.display="flex"; });
$("#help").addEventListener("click",()=>{ $("#help").style.display="none"; });

document.addEventListener("keydown",e=>{
  if(e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)){ if(e.key==="Escape") e.target.blur(); return; }
  if(e.key==="Escape"){ $("#help").style.display="none"; return; }
  const n=parseInt(e.key,10);
  if(n>=1 && n<=SCREENS.length){ showScreen(SCREENS[n-1][0]); return; }
  if(e.key==="/"){ $("#search").focus(); e.preventDefault(); return; }
  if(e.key==="?"){ $("#help").style.display="flex"; return; }
  if(e.key==="h"){ $("#t-contrast").click(); return; }
  if(e.key==="e"){ $("#t-lang").click(); return; }
  if(e.key==="j"||e.key==="k"||e.key==="ArrowDown"||e.key==="ArrowUp"){
    const rows=Array.from(document.querySelectorAll("#flist .frow[data-id]")); if(!rows.length) return;
    let i=rows.findIndex(r=>r.classList.contains("sel")); rows.forEach(r=>r.classList.remove("sel"));
    i=(e.key==="j"||e.key==="ArrowDown")?Math.min(rows.length-1,i+1):Math.max(0,i<0?0:i-1);
    rows[i].classList.add("sel"); rows[i].scrollIntoView({block:"nearest"}); e.preventDefault();
  }
  if(e.key==="Enter"){ const sel=document.querySelector("#flist .frow.sel"); if(sel) sel.click(); }
});

// inline favicon (built in JS so the served HTML carries no URL of any kind)
(function(){ try{
  const svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><path d='M8 1 2 3v5c0 4 6 7 6 7s6-3 6-7V3z' fill='%235bbf84'/></svg>";
  const link = document.createElement("link"); link.rel="icon"; link.href="data:image/svg+xml," + svg.replace(/</g,"%3C").replace(/>/g,"%3E").replace(/#/g,"%23");
  document.head.appendChild(link);
}catch(e){} })();

// ---- init
buildTabs(); loadLabels().then(applyLang); buildHelp();
refresh(); setInterval(refresh, 2500);
