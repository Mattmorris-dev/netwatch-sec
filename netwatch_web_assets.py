"""
HTML, CSS and JavaScript for the NetWatch web interface.

Static text only: no logic and no imports. netwatch.py imports these names,
so `netwatch.WEB_DASHBOARD_HTML` and the others still resolve. Kept apart so
that a change to the Python code and a change to the page do not share one
12,000-line file.
"""
# pylint: disable=line-too-long,too-many-lines

_LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch — Login</title><style>
*{margin:0;padding:0;box-sizing:border-box}body{background:#080a0e;color:#c8ccd4;font-family:'JetBrains Mono','Fira Code',monospace;
display:flex;justify-content:center;align-items:center;min-height:100vh}
.box{background:#0d1117;border:1px solid #1a1f2b;border-radius:8px;padding:40px;width:340px;text-align:center}
h1{color:#ff3333;font-size:22px;margin-bottom:8px;letter-spacing:2px}
.sub{color:#555;font-size:11px;margin-bottom:24px}
input{width:100%;background:#080a0e;border:1px solid #1a1f2b;color:#c8ccd4;font-family:inherit;
font-size:14px;padding:10px 14px;border-radius:4px;outline:none;margin-bottom:12px;text-align:center}
input:focus{border-color:#ff3333}
button{width:100%;background:#ff3333;color:#080a0e;border:none;padding:10px;border-radius:4px;
font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;letter-spacing:1px}
button:hover{background:#ff5555}
.err{color:#ff3333;font-size:11px;margin-top:8px;min-height:16px}
.div{color:#333;font-size:10px;margin:14px 0 10px;letter-spacing:1px}
a.sso{display:block;margin-top:6px;padding:10px;border:1px solid #1a1f2b;border-radius:4px;
color:#33ff99;text-decoration:none;font-size:12px;letter-spacing:1px}
a.sso:hover{border-color:#33ff99}
#mfabox{display:none}
</style></head><body><div class="box"><h1>NETWATCH</h1><div class="sub">Enter access token to continue</div>
<div id="credbox">
<input id="tok" type="password" placeholder="Token" autocomplete="off" autofocus>
<div class="div">— or sign in (Business) —</div>
<input id="usr" type="text" placeholder="Username" autocomplete="username">
<input id="pwd" type="password" placeholder="Password" autocomplete="current-password">
</div>
<div id="mfabox">
<div class="div">— two-factor code —</div>
<input id="mfa" type="text" inputmode="numeric" placeholder="6-digit code or recovery code" autocomplete="one-time-code">
</div>
<button id="go" onclick="go()">AUTHENTICATE</button><div class="err" id="err"></div>
{% if sso_enabled %}<div class="div">— or —</div>
<a class="sso" href="/auth/oidc/login">SIGN IN WITH SSO</a>{% endif %}
</div>
<script>
let challenge=null;
for(const id of ["tok","usr","pwd","mfa"])document.getElementById(id).addEventListener("keydown",e=>{if(e.key==="Enter")go()});
async function post(body){
return fetch("/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});}
async function go(){
const err=document.getElementById("err");
let body=null;
if(challenge){
const c=document.getElementById("mfa").value.trim();
if(!c)return;
body={challenge:challenge,code:c};
}else{
const t=document.getElementById("tok").value.trim();
const u=document.getElementById("usr").value.trim();
const p=document.getElementById("pwd").value;
if(t)body={token:t};else if(u&&p)body={user:u,pass:p};else return;
}
try{const r=await post(body);
let data={};try{data=await r.json()}catch(e){}
if(r.status===429){err.textContent=data.retry_after?("Locked — retry in "+data.retry_after+"s"):"Too many attempts";return}
if(r.ok&&data.mfa_required){
challenge=data.challenge;
document.getElementById("credbox").style.display="none";
document.getElementById("mfabox").style.display="block";
document.getElementById("mfa").focus();
err.textContent="";return}
if(r.ok){location.reload();return}
if(challenge){err.textContent="Invalid code"}else{err.textContent="Invalid credentials"}}
catch(e){err.textContent="Connection error"}}
</script></body></html>"""

WEB_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js" integrity="sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+6DChMTBJemed7ZnvJ" crossorigin="anonymous"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#080a0e;--surface:#0d1117;--border:#1a1f2b;--red:#ff3333;--green:#00ff88;
--cyan:#00d4ff;--yellow:#ffcc00;--magenta:#ff66ff;--blue:#4488ff;--dim:#555;--text:#c8ccd4;
--panel-h:40vh;
/* semantic aliases — components read these; theme switches still hit the literal vars */
--accent:var(--red);--fg:var(--text);--muted:var(--dim);
--threat-high:var(--red);--threat-med:var(--yellow);--threat-low:var(--green);
--warn:var(--yellow);--info:var(--cyan);--good:var(--green);
--svc-on-bg:#0a2a15;--svc-on-bd:#0f3d1e;
--svc-warn-bg:#2a2a0a;--svc-warn-bd:#3d3d0f;
--svc-off-bg:#1a0a0a;--svc-off-bd:#2a1515;--svc-off-fg:#663333;
--header-grad-from:#12060a}
.theme-matrix{--bg:#000;--surface:#001100;--border:#003300;--red:#00ff41;--green:#00ff41;
--cyan:#00ff41;--yellow:#33ff33;--magenta:#00ff41;--blue:#00ff41;--dim:#005500;--text:#00ff41;
--svc-on-bg:#002200;--svc-on-bd:#004400;--svc-warn-bg:#002200;--svc-warn-bd:#004400;
--svc-off-bg:#001100;--svc-off-bd:#002200;--svc-off-fg:#005500;--header-grad-from:#001100}
.theme-midnight{--bg:#020617;--surface:#0f172a;--border:#1e3a5f;--red:#f43f5e;--green:#34d399;
--cyan:#38bdf8;--yellow:#fbbf24;--magenta:#a78bfa;--blue:#60a5fa;--dim:#475569;--text:#e0f2fe;
--svc-on-bg:#053024;--svc-on-bd:#0a4a3a;--svc-warn-bg:#3a2a05;--svc-warn-bd:#5a420a;
--svc-off-bg:#1a0a14;--svc-off-bd:#2a1525;--svc-off-fg:#6b3d4d;--header-grad-from:#1e0a16}
.theme-cyberpunk{--bg:#050014;--surface:#111827;--border:#f97316;--red:#f97316;--green:#22d3ee;
--cyan:#22d3ee;--yellow:#f9a8d4;--magenta:#f9a8d4;--blue:#818cf8;--dim:#6b21a8;--text:#f9a8d4;
--svc-on-bg:#0a2030;--svc-on-bd:#1a3050;--svc-warn-bg:#301a30;--svc-warn-bd:#502a50;
--svc-off-bg:#1a0a1a;--svc-off-bd:#2a152a;--svc-off-fg:#6b3d6b;--header-grad-from:#1a0530}
.theme-light{--bg:#f9fafb;--surface:#ffffff;--border:#d1d5db;--red:#dc2626;--green:#047857;
--cyan:#0e7490;--yellow:#b45309;--magenta:#7e22ce;--blue:#1d4ed8;--dim:#6b7280;--text:#111827;
--svc-on-bg:#d1fae5;--svc-on-bd:#a7f3d0;--svc-warn-bg:#fef3c7;--svc-warn-bd:#fcd34d;
--svc-off-bg:#fee2e2;--svc-off-bd:#fca5a5;--svc-off-fg:#991b1b;--header-grad-from:#fee2e2}
#scanline-overlay{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:50;opacity:0}
#scanline-overlay.soft{opacity:1;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,.03) 3px,rgba(0,0,0,.03) 6px)}
#scanline-overlay.heavy{opacity:1;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.08) 2px,rgba(0,0,0,.08) 4px)}
@keyframes status-pulse{0%,100%{opacity:1}50%{opacity:.4}}
.pulse{animation:status-pulse 1.5s ease-in-out infinite}
@keyframes row-in{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:none}}
.fade-in tr,.fade-in .nw-row{animation:row-in .18s ease-out both}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{display:inline-block;width:10px;height:10px;border:2px solid var(--muted);
border-top-color:var(--accent);border-radius:50%;animation:spin .9s linear infinite;vertical-align:-1px;margin-right:6px}
.empty-state,.loading-state{padding:24px 12px;color:var(--muted);font-size:12px;
text-align:left;border:1px dashed var(--border);border-radius:6px;background:rgba(255,255,255,.01);
margin-top:4px}
.empty-state .label,.loading-state .label{color:var(--fg);font-size:13px;margin-bottom:4px}
.empty-state .hint{color:var(--muted);font-size:11px}
.loading-state .label{color:var(--info)}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono','Fira Code',monospace;
font-size:13px;overflow-x:hidden;min-height:100vh;display:flex;flex-direction:column}
#header{background:linear-gradient(180deg,var(--header-grad-from) 0%,var(--surface) 100%);
border-bottom:2px solid var(--accent);padding:10px 20px;display:flex;align-items:center;gap:16px;flex-shrink:0}
#header h1{color:var(--red);font-size:18px;font-weight:700;letter-spacing:2px}
.stat{color:var(--dim);font-size:11px}
.stat b{color:var(--text)}
.services{display:flex;gap:4px;margin-left:auto;flex-wrap:wrap}
.svc{padding:2px 6px;border-radius:3px;font-size:9px;font-weight:600;text-transform:uppercase}
.svc.on{background:var(--svc-on-bg);color:var(--good);border:1px solid var(--svc-on-bd)}
.svc.warn{background:var(--svc-warn-bg);color:var(--warn);border:1px solid var(--svc-warn-bd)}
.svc.off{background:var(--svc-off-bg);color:var(--svc-off-fg);border:1px solid var(--svc-off-bd)}
#tabs{display:flex;gap:0;background:var(--surface);border-bottom:1px solid var(--border);
padding:0 12px;flex-shrink:0;overflow-x:auto}
.tab{padding:8px 14px;cursor:pointer;color:var(--dim);font-size:11px;font-weight:600;
text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap}
.tab:hover{color:var(--text);background:rgba(255,255,255,.03)}
.tab.active{color:var(--red);border-bottom-color:var(--red);background:rgba(255,51,51,.05)}
.tab .n{font-size:9px;color:var(--dim);margin-right:3px}
#content{flex:1;overflow-y:auto;padding:14px 18px;min-height:0}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--dim);font-size:10px;text-transform:uppercase;
letter-spacing:.5px;padding:5px 8px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg)}
td{padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:rgba(255,255,255,.02)}
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:rgba(0,212,255,.06)}
.ip{color:var(--cyan)}.ip.local{color:var(--green)}
.ip.threat-high{color:var(--red)}.ip.threat-med{color:var(--yellow)}
.tag{display:inline-block;padding:1px 5px;border-radius:2px;font-size:9px;margin:0 2px;
background:rgba(255,51,51,.15);color:var(--red)}
.bar-wrap{height:12px;background:var(--border);border-radius:2px;overflow:hidden;min-width:40px}
.bar-fill{height:100%;border-radius:2px;transition:width .3s}
.proto-bar{background:var(--blue)}
.alert-row{color:var(--red)}
.hp-cred{color:var(--red)}.hp-telnet{color:var(--yellow)}.hp-ftp{color:var(--magenta)}
.hp-rtsp{color:var(--blue)}.hp-http{color:var(--dim)}
.section-title{color:var(--cyan);font-size:13px;font-weight:700;margin:14px 0 6px;
display:flex;align-items:center;gap:8px}
.section-title:first-child{margin-top:0}
.count{color:var(--dim);font-size:10px;font-weight:400}
#cmd-bar{background:var(--surface);border-top:1px solid var(--border);padding:8px 18px;
display:flex;gap:10px;align-items:center;flex-shrink:0}
#cmd-bar label{color:var(--red);font-weight:700;font-size:14px}
#cmd-input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);
font-family:inherit;font-size:13px;padding:7px 12px;border-radius:4px;outline:none}
#cmd-input:focus{border-color:var(--accent);box-shadow:0 0 8px rgba(255,51,51,.15)}
.tab:focus-visible,button:focus-visible,select:focus-visible,
.ctx-item:focus-visible,.panel-btn:focus-visible,.port-chip:focus-visible{
outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
[role="dialog"]{outline:none}
#kbd-help{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
background:var(--surface);border:1px solid var(--accent);border-radius:8px;padding:18px 22px;
z-index:1100;min-width:280px;max-width:90vw;box-shadow:0 16px 48px rgba(0,0,0,.7)}
#kbd-help.open{display:block}
#kbd-help h3{color:var(--accent);font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
#kbd-help table{width:100%;font-size:12px}
#kbd-help td{padding:3px 8px;border:none}
#kbd-help kbd{background:var(--bg);border:1px solid var(--border);border-radius:3px;
padding:1px 6px;font-family:inherit;font-size:11px;color:var(--info)}
#kbd-help .close-hint{color:var(--muted);font-size:10px;margin-top:10px;text-align:right}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
clip:rect(0,0,0,0);white-space:nowrap;border:0}
.osint-geo{color:var(--cyan)}.osint-dns{color:var(--magenta)}.osint-scan{color:var(--green)}
.osint-abuse{color:var(--red)}.osint-whois{color:var(--blue)}
.ip-click{cursor:pointer;text-decoration:none;border-bottom:1px dashed rgba(0,212,255,.3);transition:all .15s}
.ip-click:hover{border-bottom-color:var(--cyan);text-shadow:0 0 6px rgba(0,212,255,.3)}
#ctx-menu{display:none;position:fixed;background:var(--surface);border:1px solid var(--red);
border-radius:6px;padding:4px 0;z-index:1000;min-width:190px;box-shadow:0 8px 24px rgba(0,0,0,.6)}
.ctx-hdr{padding:8px 14px;color:var(--cyan);font-weight:700;font-size:12px;border-bottom:1px solid var(--border);
letter-spacing:.5px;display:flex;align-items:center;gap:6px}
.ctx-hdr::before{content:">";color:var(--red)}
.ctx-sep{height:1px;background:var(--border);margin:2px 0}
.ctx-item{padding:6px 14px;font-size:12px;cursor:pointer;color:var(--text);display:flex;align-items:center;gap:8px;transition:all .1s}
.ctx-item:hover{background:rgba(255,51,51,.1);color:var(--red)}
.ctx-item .k{color:var(--dim);font-size:10px;margin-left:auto}
#output-panel{display:none;position:fixed;bottom:0;left:0;right:0;background:var(--surface);
border-top:2px solid var(--red);z-index:900;flex-direction:column;height:var(--panel-h);min-height:120px;max-height:85vh}
#output-panel.open{display:flex}
#panel-drag{height:6px;cursor:ns-resize;background:transparent;flex-shrink:0;display:flex;align-items:center;justify-content:center}
#panel-drag::after{content:"";width:40px;height:3px;background:var(--dim);border-radius:2px}
#panel-drag:hover::after{background:var(--red)}
#output-hdr{padding:6px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);flex-shrink:0}
#output-hdr .title{color:var(--red);font-weight:700;font-size:12px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.panel-btn{cursor:pointer;color:var(--dim);font-size:14px;padding:2px 6px;border-radius:3px;border:1px solid transparent}
.panel-btn:hover{color:var(--red);border-color:var(--border)}
#output-body{overflow-y:auto;padding:10px 16px;font-size:11px;color:var(--text);flex:1;white-space:pre-wrap;font-family:inherit;line-height:1.6}
#detail-panel{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
background:var(--surface);border:2px solid var(--red);border-radius:8px;z-index:950;
width:700px;max-width:90vw;max-height:80vh;flex-direction:column;box-shadow:0 16px 48px rgba(0,0,0,.8)}
#detail-panel.open{display:flex}
#detail-hdr{padding:10px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);flex-shrink:0}
#detail-hdr .title{color:var(--cyan);font-weight:700;font-size:14px;flex:1}
#detail-body{overflow-y:auto;padding:14px 16px;font-size:12px;flex:1}
.detail-section{margin-bottom:14px}
.detail-section h3{color:var(--red);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.detail-row{display:flex;gap:12px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.detail-label{color:var(--dim);min-width:100px;font-size:11px}
.detail-val{color:var(--text);word-break:break-all}
.port-chip{display:inline-block;padding:2px 6px;margin:2px;border-radius:3px;font-size:10px;
background:rgba(0,212,255,.1);color:var(--cyan);border:1px solid rgba(0,212,255,.2)}
.osint-row{cursor:pointer;transition:background .15s}
.osint-row:hover td{background:rgba(0,212,255,.06) !important}
@media(max-width:768px){
  #header{flex-wrap:wrap;gap:8px;padding:8px 12px}
  .services{margin-left:0;width:100%}
  td,th{padding:3px 4px;font-size:11px}
  #content{padding:10px}
  #detail-panel{width:95vw}
  #charts-grid{grid-template-columns:1fr !important}
  #tabs{background:linear-gradient(90deg,var(--surface) 0%,var(--surface) 92%,rgba(0,0,0,.4) 100%)}
  .panel-btn,.tab,.ctx-item{min-height:36px;display:flex;align-items:center}
}
@media(max-width:640px){
  #detail-panel{width:100vw;max-width:100vw;height:100vh;max-height:100vh;
    border-radius:0;border-width:0;top:0;left:0;transform:none}
  #detail-panel.open{display:flex}
  .panel-btn{min-width:44px;min-height:44px;justify-content:center}
  #cmd-input{font-size:14px}
  #kbd-help{width:100vw;max-width:100vw;border-radius:0;top:0;left:0;transform:none;height:100vh;overflow-y:auto}
}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#2a3040}
</style>
</head>
<body>
<div id="header">
  <h1>NETWATCH</h1>
  {% if cam_enabled %}<a href="/cam" title="Camera Sentry (Pro)" style="color:var(--green);font-size:11px;text-decoration:none;border:1px solid var(--border);border-radius:3px;padding:3px 8px">&#9673; CAM</a>{% endif %}
  <span class="stat"><b id="s-pkts">0</b> pkts</span>
  <span class="stat"><b id="s-bytes">0B</b></span>
  <span class="stat"><b id="s-hosts">0</b> hosts</span>
  <span class="stat" style="color:var(--dim)" id="s-time"></span>
  <div class="services" id="svc-bar"></div>
  <span class="sr-only" id="theme-sel-label">Theme</span>
  <select id="theme-sel" aria-labelledby="theme-sel-label" style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:3px 6px;font-size:10px;font-family:inherit;border-radius:3px;cursor:pointer" title="Theme">
    <option value="">Terminal</option><option value="theme-matrix">Matrix</option><option value="theme-midnight">Midnight</option><option value="theme-cyberpunk">Cyberpunk</option><option value="theme-light">Light</option>
  </select>
  <span class="sr-only" id="scan-sel-label">CRT scanlines</span>
  <select id="scanline-sel" aria-labelledby="scan-sel-label" style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:3px 6px;font-size:10px;font-family:inherit;border-radius:3px;cursor:pointer" title="CRT Scanlines">
    <option value="">CRT Off</option><option value="soft">CRT Soft</option><option value="heavy">CRT Heavy</option>
  </select>
  <button id="kbd-help-btn" title="Keyboard shortcuts (press ?)" aria-label="Show keyboard shortcuts" style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:2px 8px;font-size:11px;font-family:inherit;border-radius:3px;cursor:pointer">?</button>
  <span class="pulse" style="width:8px;height:8px;border-radius:50%;background:var(--good);display:inline-block" title="Live updates streaming" aria-label="Live updates streaming"></span>
</div>
<div id="scanline-overlay"></div>
<div id="tabs"></div>
<div id="charts-row" style="display:none;padding:14px 18px 0">
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px" id="charts-grid">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;height:155px"><div style="color:var(--cyan);font-size:10px;font-weight:700;margin-bottom:2px">TRAFFIC</div><canvas id="chart-traffic"></canvas></div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;height:155px"><div style="color:var(--cyan);font-size:10px;font-weight:700;margin-bottom:2px">PROTOCOLS</div><canvas id="chart-proto"></canvas></div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;height:155px"><div style="color:var(--cyan);font-size:10px;font-weight:700;margin-bottom:2px">THREATS</div><canvas id="chart-threat"></canvas></div>
  </div>
</div>
<div id="content"></div>
<div id="cmd-bar">
  <label>nw&gt;</label>
  <input id="cmd-input" type="text" placeholder="Type command... (scan / geo / whois / recon / deep / help)  Press / to focus" autocomplete="off" spellcheck="false">
</div>
<div id="ctx-menu"></div>
<div id="output-panel" role="region" aria-label="Command output panel">
  <div id="panel-drag" role="separator" aria-orientation="horizontal" aria-label="Resize output panel"></div>
  <div id="output-hdr">
    <span class="title" id="output-title">OUTPUT</span>
    <button class="panel-btn" id="output-max" title="Maximize" aria-label="Maximize output panel">&#9634;</button>
    <button class="panel-btn" id="output-close" title="Close" aria-label="Close output panel">&times;</button>
  </div>
  <div id="output-body"></div>
</div>
<div id="detail-panel" role="dialog" aria-modal="true" aria-labelledby="detail-title">
  <div id="detail-hdr">
    <span class="title" id="detail-title">HOST DETAIL</span>
    <button class="panel-btn" id="detail-close" title="Close" aria-label="Close host detail">&times;</button>
  </div>
  <div id="detail-body"></div>
</div>
<div id="kbd-help" role="dialog" aria-modal="true" aria-labelledby="kbd-help-title">
  <h3 id="kbd-help-title">Keyboard Shortcuts</h3>
  <table>
    <tr><td><kbd>1</kbd>–<kbd>9</kbd></td><td>Jump to tab</td></tr>
    <tr><td><kbd>0</kbd></td><td>Proxy tab</td></tr>
    <tr><td><kbd>Shift</kbd>+<kbd>M</kbd></td><td>Mesh tab</td></tr>
    <tr><td><kbd>Shift</kbd>+<kbd>H</kbd></td><td>Help tab</td></tr>
    <tr><td><kbd>R</kbd></td><td>Replay tab</td></tr>
    <tr><td><kbd>/</kbd></td><td>Focus command bar</td></tr>
    <tr><td><kbd>?</kbd></td><td>Toggle this overlay</td></tr>
    <tr><td><kbd>Esc</kbd></td><td>Close any open panel</td></tr>
  </table>
  <div class="close-hint">Esc to close</div>
</div>
<script>
const TABS=["all","hosts","proto","dns","honeypot","scan","nmap","arp","alerts","osint","proxy","mesh","fleet","replay","audit","help"];
let tab="all",D={};
function $(s){return document.querySelector(s)}
function $$(s){return document.querySelectorAll(s)}
function esc(s){const d=document.createElement("div");d.textContent=s;return d.innerHTML}
function fmtBytes(b){for(const u of["B","KB","MB","GB"]){if(b<1024)return b.toFixed(1)+u;b/=1024}return b.toFixed(1)+"TB"}

function initTabs(){
  const c=$("#tabs");
  c.setAttribute("role","tablist");
  TABS.forEach((t,i)=>{
    const d=document.createElement("button");
    d.className="tab"+(t===tab?" active":"");
    d.setAttribute("role","tab");
    d.setAttribute("aria-selected",t===tab?"true":"false");
    d.style.background="transparent";d.style.border="none";d.style.borderBottom="2px solid transparent";
    d.innerHTML=`<span class="n">${i<9?i+1:0}</span>${t.toUpperCase()}`;
    d.onclick=()=>_activateTabIdx(i);
    c.appendChild(d);
  });
}

function ipClass(h){
  if(h.local)return"ip local";
  if(h.threat_score>=30)return"ip threat-high";
  if(h.threat_score>=10)return"ip threat-med";
  return"ip";
}
function hpClass(svc){
  if(["credential","malware_attempt","ftp_upload"].includes(svc))return"hp-cred";
  if(["telnet","telnet_cmd"].includes(svc))return"hp-telnet";
  if(svc.startsWith("ftp"))return"hp-ftp";
  if(svc.startsWith("rtsp"))return"hp-rtsp";
  return"hp-http";
}

function renderHosts(list,limit){
  const h=list||D.hosts||[];
  const show=h.slice(0,limit||h.length);
  let s=`<table><tr><th style="width:140px">IP</th><th style="width:160px">Hostname</th><th style="width:80px">In</th><th style="width:80px">Out</th><th style="width:60px">Pkts</th><th style="width:50px">Ports</th><th style="width:60px">Threat</th><th>Tags</th></tr>`;
  show.forEach(h=>{
    const tags=h.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join("");
    const thr=h.threat_score>0?`<span style="color:${h.threat_score>=30?'var(--red)':h.threat_score>=10?'var(--yellow)':'var(--dim)'}">${h.threat_score}</span>`:`<span style="color:var(--dim)">0</span>`;
    s+=`<tr class="clickable" onclick="showHostDetail('${esc(h.ip)}')"><td class="${ipClass(h)}"><span class="ip-click" data-ip="${esc(h.ip)}">${esc(h.ip)}</span></td><td>${esc(h.hostname)}</td><td>${fmtBytes(h.bytes_in)}</td><td>${fmtBytes(h.bytes_out)}</td><td>${h.packets.toLocaleString()}</td><td>${h.ports}</td><td>${thr}</td><td>${tags}</td></tr>`;
  });
  return s+"</table>";
}
function _empty(label,hint){return`<div class="empty-state"><div class="label">${esc(label)}</div><div class="hint">${esc(hint||"")}</div></div>`}
function _loading(label){return`<div class="loading-state"><div class="label"><span class="spinner"></span>${esc(label)}</div></div>`}
function renderProto(expanded){
  const p=D.protocols||[];
  if(!p.length)return _empty("No protocol data yet","Waiting for tshark to start capturing — check the TSHARK service indicator.");
  const max=p[0]?.count||1;
  let s=`<table><tr><th style="width:200px">Protocol</th><th style="width:100px">Count</th><th>Distribution</th></tr>`;
  p.forEach(x=>{
    const pct=((x.count/max)*100).toFixed(0);
    s+=`<tr><td style="color:var(--blue)">${esc(x.name)}</td><td>${x.count.toLocaleString()}</td><td><div class="bar-wrap"><div class="bar-fill proto-bar" style="width:${pct}%"></div></div></td></tr>`;
  });
  return s+"</table>";
}
function renderDNS(limit){
  const d=(D.dns||[]).slice(-(limit||50)).reverse();
  if(!d.length)return _empty("No DNS queries yet","Run nslookup or wait for traffic with DNS lookups.");
  let s=`<table><tr><th style="width:80px">Time</th><th style="width:140px">IP</th><th>Domain</th></tr>`;
  d.forEach(e=>{s+=`<tr><td style="color:var(--dim)">${esc(e.time)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td style="color:var(--magenta)">${esc(e.domain)}</td></tr>`});
  return s+"</table>";
}
function renderHP(limit){
  // HTTP events live in the Scan tab (they're high-volume scanner noise that drowns out
  // credential/telnet/ftp/rtsp signal). Mirrors the TUI's _section_honeypot(show_http=False) default.
  const h=(D.honeypot||[]).filter(e=>e.service!=="http").slice(-(limit||50)).reverse();
  if(!h.length)return _empty("No honeypot hits yet","Console mode shows a remote node's attacks; sensor mode listens locally on :2323 / :2121 / :8080 / :8554 (map 23/21/80/554 via NAT).");
  let s=`<table><tr><th style="width:70px">Time</th><th style="width:100px">Service</th><th style="width:130px">IP</th><th>Summary</th></tr>`;
  h.forEach(e=>{s+=`<tr><td style="color:var(--dim)">${esc(e.time)}</td><td class="${hpClass(e.service)}">${esc(e.service)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td>${esc(e.summary)}</td></tr>`});
  return s+"</table>";
}
function renderScan(limit){
  // HTTP probes split out from the honeypot tab — Mirai/CVE scanners hammer :80 constantly,
  // so this view is its own signal class (path coverage, user agents, scanner identification).
  const h=(D.honeypot||[]).filter(e=>e.service==="http").slice(-(limit||100)).reverse();
  if(!h.length)return _empty("No HTTP probes yet","HTTP scan/probe traffic appears here once attackers hit :80.");
  let s=`<table><tr><th style="width:70px">Time</th><th style="width:130px">IP</th><th>Probe</th></tr>`;
  h.forEach(e=>{s+=`<tr><td style="color:var(--dim)">${esc(e.time)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td>${esc(e.summary)}</td></tr>`});
  return s+"</table>";
}
function renderNmap(){
  const n=D.nmap||[];
  const status=D.nmap_running?`<span style="color:var(--yellow);animation:pulse 1s infinite">SCANNING...</span>`:`<span style="color:var(--dim)">idle</span>`;
  let s=`<div class="section-title">NMAP ${status} <span class="count">(${n.length} results)</span></div>`;
  if(!n.length)return s+_empty("No scans yet","Type 'scan <ip>' or 'deep <ip>' in the command bar.");
  const ips=new Set();
  n.forEach(r=>{const m=r.line.match(/(\d+\.\d+\.\d+\.\d+)/);if(m)ips.add(m[1])});
  if(ips.size){
    s+=`<div style="margin:8px 0;display:flex;gap:6px;flex-wrap:wrap">`;
    ips.forEach(ip=>{s+=`<span class="ip-click port-chip" data-ip="${esc(ip)}" onclick="showScanDetail('${esc(ip)}')" style="cursor:pointer">${esc(ip)}</span>`});
    s+=`</div>`;
  }
  s+=`<table><tr><th style="width:70px">Time</th><th>Result</th></tr>`;
  n.slice(-30).reverse().forEach(r=>{
    const m=r.line.match(/(\d+\.\d+\.\d+\.\d+)/);
    const click=m?` class="clickable" onclick="showScanDetail('${esc(m[1])}')"`:"";
    s+=`<tr${click}><td style="color:var(--dim)">${esc(r.time)}</td><td>${esc(r.line)}</td></tr>`;
  });
  return s+"</table>";
}
function renderARP(){
  const a=D.arp||[];
  if(!a.length)return _empty("No ARP entries yet","ARP monitor watches your subnet — devices appear as they speak on the wire.");
  let s=`<table><tr><th style="width:180px">MAC</th><th style="width:140px">IP</th><th>State</th></tr>`;
  a.forEach(e=>{s+=`<tr class="clickable" onclick="showHostDetail('${esc(e.ip)}')"><td style="color:var(--cyan)">${esc(e.mac)}</td><td class="ip"><span class="ip-click" data-ip="${esc(e.ip)}">${esc(e.ip)}</span></td><td style="color:var(--dim)">${esc(e.state)}</td></tr>`});
  return s+"</table>";
}
function renderAlerts(){
  const a=(D.alerts||[]).slice(-50).reverse();
  if(!a.length)return _empty("All quiet","No threat alerts yet. Alerts appear here when scoring fires or honeypots see credentials.");
  let s=`<table><tr><th style="width:70px">Time</th><th>Alert</th></tr>`;
  a.forEach(e=>{
    const m=e.msg.match(/(\d+\.\d+\.\d+\.\d+)/);
    const click=m?` class="clickable" onclick="showHostDetail('${esc(m[1])}')"`:"";
    s+=`<tr class="alert-row"${click}><td>${esc(e.time)}</td><td>${esc(e.msg)}</td></tr>`;
  });
  return s+"</table>";
}
function renderOSINT(){
  const o=(D.osint||[]).slice(-50).reverse();
  if(!o.length)return _empty("No OSINT results yet","Run geo, whois, abuse, ssl, recon, etc. — results show here as they finish.");
  let s=`<table><tr><th style="width:70px">Time</th><th style="width:60px">Type</th><th style="width:160px">Target</th><th>Result</th><th style="width:60px">Detail</th></tr>`;
  o.forEach(r=>{
    const cls={"GEO":"osint-geo","DNS":"osint-dns","SCAN":"osint-scan","ABUSE":"osint-abuse","WHOIS":"osint-whois","CRT":"osint-dns","SSL":"osint-geo","PING":"osint-scan","SECHDR":"osint-abuse","TECH":"osint-whois"}[r.type]||"";
    const isIP=/^\d+\.\d+\.\d+\.\d+$/.test(r.target);
    const detailBtn=isIP?`<span class="port-chip" style="cursor:pointer" onclick="showHostDetail('${esc(r.target)}')">View</span>`:"";
    s+=`<tr class="osint-row"><td style="color:var(--dim)">${esc(r.time)}</td><td class="${cls}" style="font-weight:700">${esc(r.type)}</td><td>${isIP?`<span class="ip-click" data-ip="${esc(r.target)}">${esc(r.target)}</span>`:esc(r.target)}</td><td style="white-space:normal;word-break:break-word">${esc(r.result)}</td><td>${detailBtn}</td></tr>`;
  });
  return s+"</table>";
}
function renderProxy(){
  let s="";
  if(D.proxy_active){s+=`<div style="color:var(--green);font-weight:700;margin-bottom:12px">PROXY ACTIVE</div>`}
  else{s+=`<div style="color:var(--dim);margin-bottom:12px">Proxy not active. Use <span style="color:var(--green)">proxy add socks5 127.0.0.1:9050</span> to configure.</div>`}
  return s;
}
let _replayCache=null,_replayCacheAt=0,_replayProto="ftp",_replayFilter="";
let _fleetCache=null,_fleetTimer=null;
function renderFleet(){
  let s=`<div class="section-title">REMOTE NODES — live <span class="count" id="fleet-count">(loading...)</span></div>`;
  s+=`<div id="fleet-body">${_loading("Connecting to remote node(s)...")}</div>`;
  setTimeout(_fleetMount,0);
  return s;
}
function _fleetMount(){
  _fleetRefresh();
  if(_fleetTimer)clearInterval(_fleetTimer);
  // auto-refresh on the node's poll cadence while this tab is open
  _fleetTimer=setInterval(()=>{ if(tab==="fleet")_fleetRefresh(); else {clearInterval(_fleetTimer);_fleetTimer=null;} }, 12000);
}
async function _fleetRefresh(){
  try{const r=await fetch("/api/fleet",{credentials:"same-origin"});_fleetCache=await r.json();}
  catch(e){_fleetCache={nodes:[],total:0};}
  _fleetPaint();
}
function _hiveNudge(){
  // One-line invite to join the community hive. Server says joined via
  // /api/state (D.hive_joined); dismissal is per-browser (localStorage).
  try{
    if((typeof D==="object"&&D&&D.hive_joined)||localStorage.getItem("nw_hive_nudge")==="off")return "";
  }catch(e){return "";}
  return `<div class="meta" style="border:1px solid var(--dim);border-radius:4px;padding:6px 10px;margin-bottom:10px">🐝 Join the hive — burned once, blocked everywhere. Run <b>join community</b> in the command bar. <a href="#" onclick="localStorage.setItem('nw_hive_nudge','off');_fleetPaint();return false" style="color:var(--dim)">dismiss</a></div>`;
}
function _fleetPaint(){
  const body=document.getElementById("fleet-body");if(!body)return;
  const d=_fleetCache||{nodes:[]};
  const cnt=document.getElementById("fleet-count");if(cnt)cnt.textContent="("+(d.total||0)+")";
  if((!d.nodes||!d.nodes.length)&&!d.apiary){
    body.innerHTML=_hiveNudge()+_empty("No fleet nodes","Track a node:  remote add droplet https://<tunnel-or-ip:9090> <web-token>  —  or run a hub:  collector  (nodes join it with:  join <hub> <id> <key>).");
    return;
  }
  let h=_hiveNudge();
  for(const n of d.nodes){
    h+=`<div class="section-title">◉ ${esc(n.name)} <span class="count">${esc(n.url)}${n.age!=null?" · "+n.age+"s ago":""}</span></div>`;
    const data=n.data;
    if(!data){h+=`<div class="empty">connecting...</div>`;continue;}
    if(data._error){h+=`<div class="empty" style="color:var(--red)">${esc(data._error)} — check url / token</div>`;continue;}
    const num=v=>(typeof v==="number"&&isFinite(v))?v:0;
    const td=(data.threat_dist&&typeof data.threat_dist==="object")?data.threat_dist:{};
    h+=`<div class="meta">Uptime ${esc(String(data.uptime||"?"))} · ${num(data.host_count)} hosts · ${num(data.total_packets).toLocaleString()} pkts · ${esc(String(data.total_bytes_fmt||"?"))} · iface ${esc(String(data.iface||"?"))}</div>`;
    h+=`<div class="meta">Threats: <span style="color:var(--red)">high=${num(td.high)}</span> med=${num(td.medium)} low=${num(td.low)} clean=${num(td.clean)}</div>`;
    const hp=Array.isArray(data.honeypot)?data.honeypot.filter(e=>e&&typeof e==="object"):[];
    if(hp.length){
      const by={};
      for(const e of hp){const ip=String(e.ip||"?");(by[ip]=by[ip]||[]).push(e);}
      h+=`<table><tr><th style="width:140px">Attacker</th><th style="width:70px">Hits</th><th>Services</th></tr>`;
      Object.entries(by).sort((a,b)=>b[1].length-a[1].length).slice(0,10).forEach(([ip,evs])=>{
        const svcs=[...new Set(evs.map(e=>String(e.service||"?")))].join(",");
        h+=`<tr><td class="ip" style="color:var(--red)">${esc(ip)}</td><td>${evs.length}</td><td>${esc(svcs)}</td></tr>`;
      });
      h+=`</table>`;
    }else{h+=`<div class="empty">No honeypot hits in the current window.</div>`;}
    const al=Array.isArray(data.alerts)?data.alerts.filter(a=>a&&typeof a==="object"):[];
    if(al.length){
      h+=`<div class="section-title">Latest alerts</div>`;
      al.slice(-6).forEach(a=>{h+=`<div class="alert-row"><span style="color:var(--dim)">${esc(String(a.time||""))}</span> ${esc(String(a.msg||""))}</div>`;});
    }
  }
  if(!d.paying&&d.total>1){h+=`<div class="empty">+${d.total-1} more node(s) hidden — upgrade to Pro for full fleet view.</div>`;}
  if(d.seats&&typeof d.seats==="object"){
    const lim=d.seats.limit,used=Number(d.seats.used||0);
    const full=(lim!=null&&used>=Number(lim));
    h+=`<div class="meta" style="${full?"color:var(--red)":""}">Hub seats: ${used}/${lim==null?"unlimited":Number(lim)}${full?" — FULL (revoke a node or upgrade)":""}</div>`;
  }
  if(d.apiary){h+=_renderApiary(d.apiary);}
  body.innerHTML=h;
}
function _renderApiary(ap){
  let h=`<div class="section-title">APIARY HUB — fleet rollup <span class="count">${Number(ap.total_events||0).toLocaleString()} events · ${Number(ap.nodes_active||0)} active</span></div>`;
  const nodes=Array.isArray(ap.nodes)?ap.nodes:[];
  if(nodes.length){
    h+=`<table><tr><th>Node</th><th style="width:80px">Events</th><th>Last seen</th></tr>`;
    nodes.slice(0,12).forEach(n=>{
      const rev=n&&n.revoked?` <span style="color:var(--red)">[revoked]</span>`:"";
      h+=`<tr><td>${esc(String((n&&(n.name||n.node_id))||"?"))}${rev}</td><td>${Number((n&&n.events)||0).toLocaleString()}</td><td style="color:var(--dim)">${esc(String((n&&n.last_seen)||"-"))}</td></tr>`;
    });
    h+=`</table>`;
  }
  const svc=Array.isArray(ap.top_services)?ap.top_services:[];
  if(svc.length){h+=`<div class="meta">Top services: ${svc.slice(0,6).map(x=>esc(String(x[0]))+":"+Number(x[1]||0)).join("  ")}</div>`;}
  const src=Array.isArray(ap.top_sources)?ap.top_sources:[];
  if(src.length){h+=`<div class="meta">Top sources: ${src.slice(0,6).map(x=>esc(String(x[0]))+"("+Number(x[1]||0)+")").join("  ")}</div>`;}
  const cx=ap.cortex;
  if(cx){
    h+=`<div class="section-title">CORTEX brain <span class="count">${Number(cx.attackers||0).toLocaleString()} attackers · ${Number(cx.trained_on||0).toLocaleString()} events · peak novelty ${Number(cx.peak_score||0)}</span></div>`;
    const at=Array.isArray(cx.top_attackers)?cx.top_attackers:[];
    if(at.length){
      h+=`<table><tr><th>Attacker</th><th style="width:70px">Novelty</th><th style="width:60px">Hits</th><th>Services</th></tr>`;
      at.slice(0,8).forEach(a=>{
        const svcs=Array.isArray(a&&a.services)?a.services.map(s=>esc(String(s))).join(", "):"";
        h+=`<tr><td>${esc(String((a&&a.ip)||"?"))}</td><td>${Number((a&&a.score)||0)}</td><td>${Number((a&&a.hits)||0).toLocaleString()}</td><td style="color:var(--dim)">${svcs}</td></tr>`;
      });
      h+=`</table>`;
    }
  }
  return h;
}
function renderReplay(){
  let s=`<div class="section-title">SESSION REPLAY
    <span class="count" id="replay-count">(loading...)</span>
    <span style="margin-left:auto;display:flex;gap:6px;align-items:center;flex-wrap:wrap">
      <input id="replay-filter" placeholder="filter ip / id..." value="${esc(_replayFilter)}"
        style="background:var(--bg);border:1px solid var(--border);color:var(--fg);font:inherit;font-size:11px;padding:3px 8px;border-radius:3px;width:160px;outline:none">
      <button onclick="_replayRefresh(true)" aria-label="Refresh sessions" title="Refresh"
        style="background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:3px 10px;border-radius:3px;cursor:pointer;font:inherit;font-size:11px">&#x21bb; Refresh</button>
    </span>
  </div>`;
  s+=`<div id="replay-body">${_loading("Loading captured sessions...")}</div>`;
  // schedule render after innerHTML flush
  setTimeout(_replayMount,0);
  return s;
}
function _replayMount(){
  const inp=document.getElementById("replay-filter");
  if(inp){
    inp.oninput=()=>{_replayFilter=inp.value.trim().toLowerCase();_replayPaint()};
    inp.focus();const v=inp.value;inp.value="";inp.value=v;
  }
  _replayRefresh(false);
}
async function _replayRefresh(force){
  const fresh=force||!_replayCache||(Date.now()-_replayCacheAt>15000);
  if(fresh){
    try{
      const r=await fetch("/api/replay");
      _replayCache=await r.json();_replayCacheAt=Date.now();
    }catch(e){_replayCache=[]}
  }
  _replayPaint();
}
function _replayPaint(){
  const body=document.getElementById("replay-body");
  const cnt=document.getElementById("replay-count");
  if(!body)return;
  const all=Array.isArray(_replayCache)?_replayCache:[];
  const f=_replayFilter;
  const rows=f?all.filter(s=>(s.session_id||"").toLowerCase().includes(f)||(s.ip||"").toLowerCase().includes(f)):all;
  if(cnt)cnt.textContent=`(${rows.length}${f?` / ${all.length}`:""} sessions)`;
  if(!rows.length){
    body.innerHTML=f?_empty("No sessions match the filter","Clear the filter to see all captured sessions.")
      :_empty("No replay sessions yet","Captured FTP/Telnet sessions land in logs/ — wait for honeypot hits or sync the droplet captures.");
    return;
  }
  let h=`<table class="fade-in"><tr>
    <th style="width:90px">When</th><th style="width:60px">Proto</th><th style="width:140px">IP</th>
    <th>Session ID</th><th style="width:80px;text-align:right">Size</th><th style="width:90px">Action</th></tr>`;
  rows.slice(0,200).forEach(s=>{
    const when=_fmtAgo(s.started_at_mtime);
    const protoCls=s.protocol==="telnet"?"hp-telnet":"hp-ftp";
    h+=`<tr><td style="color:var(--muted)">${esc(when)}</td>`+
       `<td><span class="${protoCls}" style="font-weight:600;text-transform:uppercase">${esc(s.protocol||"?")}</span></td>`+
       `<td class="ip"><span class="ip-click" data-ip="${esc(s.ip||"")}">${esc(s.ip||"")}</span></td>`+
       `<td style="color:var(--fg);font-size:11px">${esc(s.session_id)}</td>`+
       `<td style="text-align:right;color:var(--muted)">${(s.event_count||0).toLocaleString()}</td>`+
       `<td><button onclick="showReplayDetail('${esc(s.session_id)}','${esc(s.protocol||"ftp")}')" `+
       `aria-label="Replay session ${esc(s.session_id)}" `+
       `style="background:var(--accent);color:var(--bg);border:none;padding:3px 10px;border-radius:3px;cursor:pointer;font:inherit;font-size:11px;font-weight:600">&#9658; Play</button></td></tr>`;
  });
  h+=`</table>`;
  if(rows.length>200)h+=`<div style="color:var(--muted);font-size:11px;padding:8px 0">Showing 200 of ${rows.length}. Use the filter to narrow.</div>`;
  body.innerHTML=h;
}
function _fmtAgo(iso){
  if(!iso)return"—";
  const t=new Date(iso).getTime();
  if(!t)return iso;
  const s=Math.max(0,Math.floor((Date.now()-t)/1000));
  if(s<60)return s+"s ago";
  if(s<3600)return Math.floor(s/60)+"m ago";
  if(s<86400)return Math.floor(s/3600)+"h ago";
  return Math.floor(s/86400)+"d ago";
}
function showReplayDetail(sid,proto){
  const p=$("#detail-panel"),b=$("#detail-body"),t=$("#detail-title");
  t.textContent=`Replay: ${sid} (${proto.toUpperCase()})`;
  b.innerHTML=`<iframe src="/replay/${encodeURIComponent(sid)}?proto=${encodeURIComponent(proto)}" `+
    `title="Session replay player for ${esc(sid)}" `+
    `style="width:100%;height:70vh;border:1px solid var(--border);border-radius:4px;background:var(--bg)"></iframe>`;
  p.classList.add("open");
}

function renderMesh(){
  if(!D.mesh_connected)return _empty("Meshtastic not connected","Plug a LoRa radio (T-Beam / Heltec) over USB and restart NetWatch.");
  let s=`<div style="color:var(--green);font-weight:700;margin-bottom:8px">MESH RADIO CONNECTED</div>`;
  s+=`<div style="margin-bottom:12px;color:var(--dim)">Nodes: ${D.mesh_nodes||0} | Messages: ${D.mesh_msgs||0} | Alert forwarding: ${D.mesh_alert_fwd?"ON":"OFF"}</div>`;
  s+=`<div style="margin-bottom:8px"><input id="mesh-input" type="text" placeholder="Send mesh message..." style="background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:inherit;font-size:12px;padding:6px 10px;border-radius:4px;width:60%;outline:none"><button onclick="sendMesh()" style="background:var(--green);color:var(--bg);border:none;padding:6px 14px;margin-left:6px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700">SEND</button></div>`;
  return s;
}
function renderHelp(){
  const S="color:var(--cyan);font-size:13px;font-weight:700;margin:16px 0 8px;border-bottom:1px solid var(--border);padding-bottom:4px";
  const C="color:var(--green)";
  const D2="color:var(--dim);font-size:11px";
  let s=`<div style="max-width:800px">`;
  s+=`<div style="color:var(--red);font-size:16px;font-weight:700;margin-bottom:4px">NETWATCH COMMAND REFERENCE</div>`;
  s+=`<div style="${D2};margin-bottom:16px">Type any command in the bar below. Use @N to reference IPs by index from the hosts list.</div>`;
  s+=`<div style="${S}">OSINT (16 tools)</div><table>`;
  s+=`<tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  const osint=[["geo &lt;ip&gt;","IP geolocation"],["whois &lt;ip/domain&gt;","WHOIS lookup"],["dnsinfo &lt;domain&gt;","DNS enumeration (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV)"],
    ["rdns &lt;ip&gt;","Reverse DNS (PTR)"],["ssl &lt;host&gt; [port]","TLS certificate inspection"],["secheaders &lt;url&gt;","Security header audit + grade"],
    ["techstack &lt;url&gt;","Web technology fingerprinting"],["ping &lt;ip&gt; [count]","Jitter analysis + TTL OS guess"],
    ["health &lt;target&gt;","Full profile (ping + SSL + headers + tech + geo + DNS)"],["etrace &lt;target&gt;","Enriched traceroute with per-hop GeoIP"],
    ["portscan &lt;ip&gt;","Socket-based top 1000 port scan"],["subnet [cidr]","Threaded ping sweep"],
    ["crt &lt;domain&gt;","Certificate transparency search"],["headers &lt;url&gt;","HTTP response headers"],
    ["asn &lt;ip&gt;","ASN/BGP info"],["abuse &lt;ip&gt;","IP reputation check"],["speed","Network speed test"],["ifinfo","Local interface + routing info"]];
  osint.forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Scanning</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["scan &lt;ip&gt; [preset]","Nmap scan (quick/syn/udp/ping/full)"],["deep &lt;ip&gt;","All ports + vuln scripts"],["cve &lt;ip|CVE-id&gt;","Known CVEs, exploited first"],
   ["stealth &lt;ip&gt;","SYN scan through Tor"],["recon &lt;ip&gt;","Full OSINT profile"],["fullrecon &lt;ip&gt;","7-phase recon chain"],
   ["sweep [cidr]","ARP + ping + port scan"],["banner &lt;ip&gt; &lt;port&gt;","Service banner grab"],["trace &lt;ip&gt;","Traceroute"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Tracking &amp; Capture</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["track &lt;ip&gt; [secs]","Live packet tail (tshark)"],["untrack &lt;ip&gt;","Stop tracking"],
   ["conns &lt;ip&gt;","TCP conversation capture"],["sniff &lt;ip&gt; [secs]","Raw payload capture"],
   ["trackdns &lt;ip&gt;","DNS query capture"],["tracking","List active tracks"],
   ["pcap start/stop","PCAP recording to file"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Smart Filters</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["top [n]","Top N talkers"],["sus","Suspicious hosts (threat > 0)"],["new [mins]","Recently appeared"],
   ["loud","Most ports touched"],["find &lt;pattern&gt;","Search all data"],["ports &lt;port&gt;","Hosts using port"],
   ["country &lt;CC&gt;","Filter by country"],["whowatch","Active attackers"],["summary","Network overview"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Attack Analysis</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["inspect [n]","View honeypot event detail"],["analyze &lt;ip&gt;","Attacker profile"],
   ["decode &lt;data&gt;","Decode payload"],["sessions","All attacker IPs"],
   ["attackers","Honeypot IPs"],["profile &lt;ip&gt;","Recon report"],
   ["timeline &lt;ip&gt;","Full event history"],["report &lt;ip&gt;","Save full report"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Defense</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["block &lt;ip&gt;","iptables DROP"],["unblock &lt;ip&gt;","Remove block"],
   ["blocked","List current rules"],["diffarp","ARP table change detection"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Tags, Notes &amp; Watchlist</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["tag &lt;ip&gt; &lt;label&gt;","Label an IP"],["tag list","Show all tags"],["note &lt;ip&gt; &lt;text&gt;","Add note"],
   ["watch &lt;ip&gt;","Add to watchlist"],["watch list","Show watchlist"],["watch rm &lt;ip&gt;","Remove from watchlist"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Batch Operations</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["scanall [list]","Scan all IPs in list"],["reconall [list]","Full recon all"],
   ["geoall [list]","Geolocate all"],["whoisall [list]","WHOIS all"],
   ["blockall attackers","Block all honeypot IPs"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${D2};margin-top:8px">Lists: hosts, attackers, arp, nmap, watchlist, tracked, blocked</div>`;
  s+=`<div style="${S}">Proxy / Tor</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["proxy add &lt;type&gt; &lt;h:p&gt;","Add proxy (socks4/socks5/http)"],["proxy list","Show configured proxies"],
   ["proxy test [n]","Test proxy connection"],["proxy start","Start Tor circuits"],["proxy rotate","Toggle rotation"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Mesh Radio</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["mesh send &lt;text&gt;","Send mesh message"],["mesh status","Connection info"],
   ["mesh nodes","List mesh nodes"],["mesh alert on/off","Toggle alert forwarding"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${S}">Export &amp; System</div><table><tr><th style="width:180px">Command</th><th>Description</th></tr>`;
  [["exportips [list]","Save IPs to file"],["report &lt;ip&gt;","Full text report"],
   ["export","Save traffic JSON"],["clear","Clear output"],
   ["status","Service info"],["help","This page"]
  ].forEach(([c,d])=>{s+=`<tr><td style="${C}">${c}</td><td>${d}</td></tr>`});
  s+=`</table>`;
  s+=`<div style="${D2};margin-top:16px;border-top:1px solid var(--border);padding-top:8px">Keyboard: 1-0 = tab switch &nbsp;|&nbsp; / = focus command bar &nbsp;|&nbsp; ESC = close panels &nbsp;|&nbsp; Click any IP for context menu</div>`;
  s+=`</div>`;
  return s;
}

let _charts={};
function _css(n){return getComputedStyle(document.body).getPropertyValue(n).trim()||"#c8ccd4"}
function _rgba(hex,a){
  const h=hex.replace("#","");
  if(h.length!==3&&h.length!==6)return hex;
  const v=h.length===3?h.split("").map(c=>c+c).join(""):h;
  const r=parseInt(v.slice(0,2),16),g=parseInt(v.slice(2,4),16),b=parseInt(v.slice(4,6),16);
  return`rgba(${r},${g},${b},${a})`;
}
function _chartPalette(){
  return{
    fg:_css("--fg"),muted:_css("--muted"),accent:_css("--accent"),
    info:_css("--info"),good:_css("--good"),warn:_css("--warn"),
    magenta:_css("--magenta"),blue:_css("--blue"),
    threatHigh:_css("--threat-high"),threatMed:_css("--threat-med"),threatLow:_css("--threat-low"),
    grid:_rgba(_css("--fg")||"#fff",.05),gridSubtle:_rgba(_css("--fg")||"#fff",.03)
  };
}
function initCharts(){
  if(typeof Chart==="undefined")return;
  if(_charts.traffic)return;
  const ctx1=document.getElementById("chart-traffic");
  const ctx2=document.getElementById("chart-proto");
  const ctx3=document.getElementById("chart-threat");
  if(!ctx1||!ctx2||!ctx3)return;
  const p=_chartPalette();
  const cfg={responsive:true,maintainAspectRatio:false,animation:{duration:300},
    plugins:{legend:{labels:{color:p.fg,font:{size:10}}}}};
  _charts.traffic=new Chart(ctx1,{type:"line",data:{labels:[],datasets:[
    {label:"Packets",data:[],borderColor:p.info,backgroundColor:_rgba(p.info,.1),fill:true,tension:.3,pointRadius:0},
    {label:"Bytes (KB)",data:[],borderColor:p.accent,backgroundColor:_rgba(p.accent,.1),fill:true,tension:.3,pointRadius:0,yAxisID:"y1"}
  ]},options:{...cfg,scales:{x:{ticks:{color:p.muted,maxTicksLimit:8},grid:{color:p.gridSubtle}},
    y:{ticks:{color:p.info},grid:{color:p.grid}},
    y1:{position:"right",ticks:{color:p.accent},grid:{drawOnChartArea:false}}}}});
  _charts.proto=new Chart(ctx2,{type:"doughnut",data:{labels:[],datasets:[{data:[],
    backgroundColor:[p.info,p.accent,p.good,p.warn,p.magenta,p.blue,p.threatMed,p.threatLow,p.fg,p.muted]}]},
    options:{...cfg,plugins:{...cfg.plugins,legend:{position:"right",labels:{color:p.fg,font:{size:10},padding:8}}}}});
  _charts.threat=new Chart(ctx3,{type:"bar",data:{labels:["Clean","Low","Medium","High"],datasets:[{data:[0,0,0,0],
    backgroundColor:[_rgba(p.good,.15),_rgba(p.warn,.15),_rgba(p.threatMed,.18),_rgba(p.threatHigh,.2)],
    borderColor:[p.good,p.warn,p.threatMed,p.threatHigh],borderWidth:1}]},
    options:{...cfg,plugins:{...cfg.plugins,legend:{display:false}},
    scales:{x:{ticks:{color:p.muted},grid:{color:p.gridSubtle}},
    y:{ticks:{color:p.muted},grid:{color:p.grid}}}}});
}
function _destroyCharts(){
  ["traffic","proto","threat"].forEach(k=>{if(_charts[k]){_charts[k].destroy();delete _charts[k]}});
}

let _tsData=[];
function updateCharts(){
  if(!_charts.traffic)return;
  const td=D.threat_dist||{};
  _charts.threat.data.datasets[0].data=[td.clean||0,td.low||0,td.medium||0,td.high||0];
  _charts.threat.update();
  const p=D.protocols||[];
  _charts.proto.data.labels=p.map(x=>x.name);
  _charts.proto.data.datasets[0].data=p.map(x=>x.count);
  _charts.proto.update();
}
function loadTimeseries(){
  fetch("/api/timeseries").then(r=>r.json()).then(samples=>{
    if(!_charts.traffic||!samples.length)return;
    _tsData=samples;
    const labels=samples.map(s=>{const d=new Date(s.ts*1000);return d.getHours()+":"+String(d.getMinutes()).padStart(2,"0")});
    let prevPkts=samples[0].packets;let prevBytes=samples[0].bytes;
    const pktRates=[];const byteRates=[];
    samples.forEach((s,i)=>{
      if(i===0){pktRates.push(0);byteRates.push(0);return}
      pktRates.push(s.packets-prevPkts);
      byteRates.push(Math.round((s.bytes-prevBytes)/1024));
      prevPkts=s.packets;prevBytes=s.bytes;
    });
    _charts.traffic.data.labels=labels;
    _charts.traffic.data.datasets[0].data=pktRates;
    _charts.traffic.data.datasets[1].data=byteRates;
    _charts.traffic.update();
  }).catch(()=>{});
}

function render(){
  const c=$("#content"),cr=$("#charts-row");
  let html="";
  if(tab==="all"){
    cr.style.display="block";
    html+=`<div class="section-title">HOSTS <span class="count">(${D.host_count||0})</span></div>`;
    html+=renderHosts(null,10);
    html+=`<div class="section-title">PROTOCOLS <span class="count">(${(D.protocols||[]).length})</span></div>`;
    html+=renderProto();
    html+=`<div class="section-title">DNS <span class="count">(${(D.dns||[]).length})</span></div>`;
    html+=renderDNS(5);
    html+=`<div class="section-title">HONEYPOT <span class="count">(${(D.honeypot||[]).filter(e=>e.service!=="http").length})</span></div>`;
    html+=renderHP(5);
    if((D.alerts||[]).length){html+=`<div class="section-title" style="color:var(--red)">ALERTS <span class="count">(${D.alerts.length})</span></div>`;html+=renderAlerts()}
  }else{cr.style.display="none"}
  if(tab==="hosts"){
    html+=`<div class="section-title">HOSTS <span class="count">(${D.host_count||0})</span></div>`;
    html+=renderHosts();
  }else if(tab==="proto"){
    html+=`<div class="section-title">PROTOCOLS</div>`;
    html+=renderProto(true);
  }else if(tab==="dns"){
    html+=`<div class="section-title">DNS QUERIES</div>`;
    html+=renderDNS();
  }else if(tab==="honeypot"){
    html+=`<div class="section-title">HONEYPOT EVENTS</div>`;
    html+=renderHP();
  }else if(tab==="scan"){
    html+=`<div class="section-title">SCAN PROBES <span class="count">(${(D.honeypot||[]).filter(e=>e.service==="http").length})</span></div>`;
    html+=renderScan();
  }else if(tab==="nmap"){
    html+=renderNmap();
  }else if(tab==="arp"){
    html+=`<div class="section-title">DEVICES (ARP) <span class="count">(${(D.arp||[]).length})</span></div>`;
    html+=renderARP();
  }else if(tab==="alerts"){
    html+=`<div class="section-title" style="color:var(--red)">ALERTS <span class="count">(${(D.alerts||[]).length})</span></div>`;
    html+=renderAlerts();
  }else if(tab==="osint"){
    html+=`<div class="section-title">OSINT RESULTS <span class="count">(${(D.osint||[]).length})</span></div>`;
    html+=renderOSINT();
  }else if(tab==="proxy"){
    html+=`<div class="section-title">PROXY / TOR</div>`;
    html+=renderProxy();
  }else if(tab==="mesh"){
    html+=`<div class="section-title">MESH RADIO</div>`;
    html+=renderMesh();
  }else if(tab==="fleet"){
    html+=renderFleet();
  }else if(tab==="replay"){
    html+=renderReplay();
  }else if(tab==="audit"){
    html+=renderAudit();
  }else if(tab==="help"){
    html+=renderHelp();
  }
  c.innerHTML=html;
  if(tab==="all"){initCharts();updateCharts()}
  if(tab==="audit"){loadAudit()}
}

let _auditCache=null;
async function loadAudit(){
  try{const r=await fetch("/api/audit",{credentials:"same-origin"});_auditCache=await r.json();}
  catch(e){_auditCache={error:"fetch failed"};}
  const el=document.getElementById("audit-body");if(el)el.innerHTML=_auditPaint();
}
function _auditPaint(){
  const d=_auditCache;if(!d)return `<div class="empty">loading…</div>`;
  if(d.error)return `<div class="empty" style="color:var(--red)">${esc(String(d.error))}</div>`;
  if(d.enabled===false)return _empty("Audit trail (Enterprise)",esc(String(d.hint||"Enterprise feature")));
  const recs=Array.isArray(d.records)?d.records:[];
  const v=d.verify||{};
  let h=v.ok?`<div class="meta" style="color:var(--green)">✓ Hash chain intact — ${Number(v.records||recs.length)} records</div>`
            :`<div class="meta" style="color:var(--red)">✗ TAMPER DETECTED: ${esc(String(v.error||"chain broken"))}</div>`;
  if(!recs.length)return h+_empty("No audit records yet","Actions like block, login, and license changes are chained here.");
  h+=`<table><tr><th style="width:150px">Time</th><th style="width:80px">Actor</th><th style="width:150px">Action</th><th>Detail</th></tr>`;
  recs.slice().reverse().forEach(r=>{
    h+=`<tr><td style="color:var(--dim)">${esc(String(r.ts||"").slice(0,19))}</td><td>${esc(String(r.actor||""))}</td><td>${esc(String(r.action||""))}</td><td style="color:var(--dim)">${esc(JSON.stringify(r.detail||{}))}</td></tr>`;
  });
  return h+`</table>`;
}
function renderAudit(){
  return `<div class="section-title">AUDIT TRAIL <span class="count">tamper-evident</span></div><div id="audit-body"><div class="empty">loading…</div></div>`;
}

function updateHeader(){
  $("#s-time").textContent=D.time||"";
  $("#s-pkts").textContent=(D.total_packets||0).toLocaleString();
  $("#s-bytes").textContent=D.total_bytes_fmt||"0B";
  $("#s-hosts").textContent=D.host_count||0;
  const svcs=[
    ["SNIFF",true],["TSHARK",(D.protocols||[]).length>0],
    ["TCPDUMP",D.tcpdump_active],["NMAP",D.nmap_running],["TOR",D.proxy_active],
    ["MESH",D.mesh_connected]
  ];
  $("#svc-bar").innerHTML=svcs.map(([n,on])=>`<span class="svc ${on?"on":n==="NMAP"?"warn":"off"}">${n}</span>`).join("");
}

let evtSrc,_tsCounter=0;
let _lastCounts="",_renderPending=false;
let _sseBackoff=1000,_sseExpired=false;
function _sseStatus(state){
  const dot=document.querySelector("#header .pulse");
  if(!dot)return;
  if(state==="ok"){dot.style.background="var(--good)";dot.title="Live updates streaming"}
  else if(state==="retry"){dot.style.background="var(--warn)";dot.title="Reconnecting..."}
  else if(state==="expired"){dot.style.background="var(--threat-high)";dot.title="Session expired"}
}
function _showAuthExpired(){
  if(_sseExpired)return;
  _sseExpired=true;
  const wrap=document.createElement("div");
  wrap.id="auth-expired";
  wrap.setAttribute("role","alertdialog");
  wrap.style.cssText="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);z-index:1200;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)";
  wrap.innerHTML=`<div style="background:var(--surface);border:1px solid var(--threat-high);border-radius:8px;padding:22px 28px;max-width:90vw;width:380px;text-align:center">
    <div style="color:var(--threat-high);font-weight:700;font-size:14px;margin-bottom:10px">SESSION EXPIRED</div>
    <div style="color:var(--fg);font-size:12px;margin-bottom:14px;line-height:1.5">Your auth cookie is no longer valid (token rotation or restart).<br>Reload and paste the current token.</div>
    <button onclick="location.reload()" style="background:var(--accent);color:var(--bg);border:none;padding:8px 22px;border-radius:4px;cursor:pointer;font:inherit;font-weight:600">Reload</button>
  </div>`;
  document.body.appendChild(wrap);
}
function connect(){
  if(_sseExpired)return;
  try{evtSrc=new EventSource("/api/stream")}catch(e){console.warn("SSE construct failed:",e);return}
  evtSrc.onopen=()=>{_sseBackoff=1000;_sseStatus("ok")};
  evtSrc.onmessage=e=>{
    try{
      D=JSON.parse(e.data);
      updateHeader();
      const counts=`${D.host_count}|${(D.dns||[]).length}|${(D.honeypot||[]).length}|${(D.nmap||[]).length}|${(D.alerts||[]).length}|${(D.osint||[]).length}|${(D.arp||[]).length}|${D.nmap_running}|${tab}`;
      if(counts!==_lastCounts&&tab!=="replay"){
        _lastCounts=counts;
        if(!_renderPending){
          _renderPending=true;
          requestAnimationFrame(()=>{
            const el=$("#content");
            const scrollY=el?el.scrollTop:0;
            render();
            if(el)el.scrollTop=scrollY;
            _renderPending=false;
          });
        }
      }
      if(tab==="all"&&_charts.traffic){updateCharts();_tsCounter++;if(_tsCounter%10===0)loadTimeseries()}
    }catch(err){console.warn("SSE parse error:",err)}
  };
  evtSrc.onerror=()=>{
    if(evtSrc){evtSrc.close();evtSrc=null}
    // Probe / to detect 401 vs simple disconnect — if 401, prompt re-auth.
    fetch("/api/state",{credentials:"same-origin"}).then(r=>{
      if(r.status===401){_showAuthExpired();_sseStatus("expired");return}
      _sseStatus("retry");
      setTimeout(connect,_sseBackoff);
      _sseBackoff=Math.min(_sseBackoff*2,30000);
    }).catch(()=>{
      _sseStatus("retry");
      setTimeout(connect,_sseBackoff);
      _sseBackoff=Math.min(_sseBackoff*2,30000);
    });
  };
}

async function sendMesh(){
  const inp=document.getElementById("mesh-input");
  if(!inp)return;
  const text=inp.value.trim();
  if(!text)return;
  inp.value="";
  try{
    await fetch("/api/mesh/send",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
  }catch(e){}
}

const CTX_ACTIONS=[
  {label:"View Detail",cmd:"_detail",k:"v"},
  {sep:true},
  {label:"Scan",cmd:"scan",k:"s"},{label:"Deep Scan",cmd:"deep",k:"d"},
  {label:"Geo",cmd:"geo",k:"g"},{label:"Whois",cmd:"whois",k:"w"},
  {label:"DNS Info",cmd:"dnsinfo",k:""},{label:"Abuse",cmd:"abuse",k:""},
  {label:"ASN",cmd:"asn",k:""},{label:"SSL Cert",cmd:"ssl",k:""},
  {sep:true},
  {label:"Traceroute",cmd:"trace",k:"t"},{label:"Ping",cmd:"ping",k:"p"},
  {label:"Port Scan",cmd:"portscan",k:""},
  {sep:true},
  {label:"Analyze",cmd:"analyze",k:"a"},{label:"Timeline",cmd:"timeline",k:""},
  {label:"Full Recon",cmd:"fullrecon",k:"f"},
  {sep:true},
  {label:"Tag",cmd:"tag",k:"",prompt:true},{label:"Watch",cmd:"watch",k:""},
  {label:"Note",cmd:"note",k:"",prompt:true},
];

function showCtxMenu(ip,x,y){
  const m=$("#ctx-menu");
  let html=`<div class="ctx-hdr">${esc(ip)}</div>`;
  CTX_ACTIONS.forEach(a=>{
    if(a.sep){html+=`<div class="ctx-sep"></div>`;return}
    html+=`<div class="ctx-item" data-cmd="${a.cmd}" data-ip="${esc(ip)}" data-prompt="${a.prompt||false}">${a.label}${a.k?`<span class="k">${a.k}</span>`:""}</div>`;
  });
  m.innerHTML=html;
  m.style.left=Math.min(x,window.innerWidth-200)+"px";
  m.style.top=Math.min(y,window.innerHeight-m.scrollHeight-20)+"px";
  m.style.display="block";
  m.querySelectorAll(".ctx-item").forEach(el=>{
    el.onclick=()=>{
      const cmd=el.dataset.cmd,ip=el.dataset.ip;
      m.style.display="none";
      if(cmd==="_detail"){showHostDetail(ip);return}
      if(el.dataset.prompt==="true"){
        const val=prompt(cmd+" "+ip+" — enter value:");
        if(val)runCmd(cmd+" "+ip+" "+val);
      }else{runCmd(cmd+" "+ip)}
    };
  });
}

function showOutput(title,lines){
  const p=$("#output-panel");
  $("#output-title").textContent=title;
  $("#output-body").innerHTML=lines.map(l=>esc(l)).join("\n");
  p.classList.add("open");
}

async function runCmd(cmd){
  showOutput("Running: "+cmd,["..."]);
  try{
    const r=await fetch("/api/cmd",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cmd})});
    const d=await r.json();
    if(d.error){showOutput("Error",["Error: "+d.error])}
    else{showOutput(cmd,d.output||["(no output)"])}
  }catch(err){showOutput("Error",["Connection error: "+err.message])}
}

async function showHostDetail(ip){
  const p=$("#detail-panel"),b=$("#detail-body"),t=$("#detail-title");
  t.textContent="Loading "+ip+"...";
  b.innerHTML=`<div style="color:var(--dim)">Fetching...</div>`;
  p.classList.add("open");
  try{
    const r=await fetch("/api/host/"+ip);
    const d=await r.json();
    if(d.error){b.innerHTML=`<div style="color:var(--red)">${esc(d.error)}</div>`;t.textContent=ip;return}
    t.textContent=ip+(d.hostname?` (${d.hostname})`:"");
    let html=`<div class="detail-section"><h3>Overview</h3>`;
    html+=`<div class="detail-row"><span class="detail-label">Traffic In</span><span class="detail-val">${fmtBytes(d.bytes_in)}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Traffic Out</span><span class="detail-val">${fmtBytes(d.bytes_out)}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Packets</span><span class="detail-val">${(d.packets||0).toLocaleString()}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Threat Score</span><span class="detail-val" style="color:${d.threat_score>=30?'var(--red)':d.threat_score>=10?'var(--yellow)':'var(--green)'}">${d.threat_score}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">First Seen</span><span class="detail-val">${esc(d.first_seen||"—")}</span></div>`;
    html+=`<div class="detail-row"><span class="detail-label">Last Seen</span><span class="detail-val">${esc(d.last_seen||"—")}</span></div>`;
    if(d.geo)html+=`<div class="detail-row"><span class="detail-label">Geo</span><span class="detail-val">${esc(d.geo)}</span></div>`;
    if(d.asn)html+=`<div class="detail-row"><span class="detail-label">ASN</span><span class="detail-val">${esc(d.asn)}</span></div>`;
    if(d.notes)html+=`<div class="detail-row"><span class="detail-label">Notes</span><span class="detail-val" style="color:var(--yellow)">${esc(d.notes)}</span></div>`;
    if(d.watchlisted)html+=`<div class="detail-row"><span class="detail-label">Status</span><span class="detail-val" style="color:var(--red)">WATCHLISTED</span></div>`;
    html+=`</div>`;
    if(d.ports&&d.ports.length){
      html+=`<div class="detail-section"><h3>Open Ports (${d.ports.length})</h3><div style="display:flex;flex-wrap:wrap;gap:4px">`;
      d.ports.forEach(p=>{html+=`<span class="port-chip">${p}</span>`});
      html+=`</div></div>`;
    }
    if(d.tags&&d.tags.length){
      html+=`<div class="detail-section"><h3>Tags</h3><div style="display:flex;gap:4px;flex-wrap:wrap">`;
      d.tags.forEach(t=>{html+=`<span class="tag">${esc(t)}</span>`});
      html+=`</div></div>`;
    }
    if(d.nmap_results&&d.nmap_results.length){
      html+=`<div class="detail-section"><h3>Scan Results (${d.nmap_results.length})</h3>`;
      d.nmap_results.forEach(r=>{html+=`<div style="padding:2px 0;color:var(--green);font-size:11px">${esc(r.line)}</div>`});
      html+=`</div>`;
    }
    if(d.osint_results&&d.osint_results.length){
      html+=`<div class="detail-section"><h3>OSINT (${d.osint_results.length})</h3>`;
      d.osint_results.forEach(r=>{html+=`<div style="padding:2px 0;font-size:11px"><span style="color:var(--cyan);font-weight:700;margin-right:8px">${esc(r.type)}</span>${esc(r.result)}</div>`});
      html+=`</div>`;
    }
    if(d.honeypot_events&&d.honeypot_events.length){
      html+=`<div class="detail-section"><h3>Honeypot Activity (${d.honeypot_events.length})</h3>`;
      d.honeypot_events.forEach(e=>{html+=`<div style="padding:2px 0;font-size:11px"><span style="color:var(--dim)">${esc(e.time)}</span> <span style="color:var(--red)">${esc(e.service)}</span> ${esc(e.summary)}</div>`});
      html+=`</div>`;
    }
    if(d.dns_queries&&d.dns_queries.length){
      html+=`<div class="detail-section"><h3>DNS Queries (${d.dns_queries.length})</h3>`;
      d.dns_queries.forEach(q=>{html+=`<div style="padding:2px 0;font-size:11px"><span style="color:var(--dim)">${esc(q.time)}</span> <span style="color:var(--magenta)">${esc(q.domain)}</span></div>`});
      html+=`</div>`;
    }
    if(d.has_recon){
      html+=`<div class="detail-section"><h3>Full Recon</h3><button onclick="showReconDetail('${esc(ip)}')" style="background:var(--red);color:white;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700">View Recon Report</button></div>`;
    }
    html+=`<div style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap">`;
    ["scan","deep","geo","whois","abuse","recon","portscan","trace","ping"].forEach(cmd=>{
      html+=`<button onclick="runCmd('${cmd} ${esc(ip)}')" style="background:var(--surface);color:var(--text);border:1px solid var(--border);padding:4px 10px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:11px">${cmd}</button>`;
    });
    html+=`</div>`;
    b.innerHTML=html;
  }catch(err){b.innerHTML=`<div style="color:var(--red)">Error: ${esc(err.message)}</div>`}
}

async function showScanDetail(ip){
  const p=$("#detail-panel"),b=$("#detail-body"),t=$("#detail-title");
  t.textContent="Scan Logs: "+ip;
  b.innerHTML=`<div style="color:var(--dim)">Loading scan data...</div>`;
  p.classList.add("open");
  try{
    const r=await fetch("/api/scan_log/"+ip);
    const d=await r.json();
    let html="";
    if(d.scans&&d.scans.length){
      d.scans.forEach(s=>{
        html+=`<div class="detail-section"><h3>${esc(s.file)}</h3><pre style="background:var(--bg);padding:10px;border-radius:4px;overflow-x:auto;font-size:11px;color:var(--green);border:1px solid var(--border)">${esc(s.content)}</pre></div>`;
      });
    }else{
      html=`<div style="color:var(--dim)">No scan logs found for ${esc(ip)}</div>`;
      html+=`<button onclick="runCmd('scan ${esc(ip)}');$('#detail-panel').classList.remove('open')" style="background:var(--red);color:white;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700;margin-top:12px">Run Scan Now</button>`;
    }
    b.innerHTML=html;
  }catch(err){b.innerHTML=`<div style="color:var(--red)">Error: ${esc(err.message)}</div>`}
}

async function showReconDetail(ip){
  const b=$("#detail-body");
  b.innerHTML=`<div style="color:var(--dim)">Loading recon report...</div>`;
  try{
    const r=await fetch("/api/recon/"+ip);
    const d=await r.json();
    if(d.error){b.innerHTML=`<div style="color:var(--red)">${esc(d.error)}</div>`;return}
    let html=`<div class="detail-section"><h3>Recon Report: ${esc(ip)}</h3>`;
    Object.entries(d).forEach(([k,v])=>{
      if(k==="ip"||k==="timestamp")return;
      const val=Array.isArray(v)?v.join(", "):typeof v==="object"?JSON.stringify(v):String(v);
      if(val&&val!=="[]"&&val!=="{}")html+=`<div class="detail-row"><span class="detail-label">${esc(k)}</span><span class="detail-val" style="white-space:normal">${esc(val)}</span></div>`;
    });
    html+=`</div>`;
    b.innerHTML=html;
  }catch(err){b.innerHTML=`<div style="color:var(--red)">Error: ${esc(err.message)}</div>`}
}

// Resizable output panel
(function(){
  const drag=$("#panel-drag"),panel=$("#output-panel");
  let startY,startH;
  drag.addEventListener("mousedown",e=>{
    startY=e.clientY;startH=panel.offsetHeight;
    const onMove=e2=>{
      const h=startH+(startY-e2.clientY);
      panel.style.height=Math.max(120,Math.min(window.innerHeight*.85,h))+"px";
    };
    const onUp=()=>{document.removeEventListener("mousemove",onMove);document.removeEventListener("mouseup",onUp)};
    document.addEventListener("mousemove",onMove);
    document.addEventListener("mouseup",onUp);
    e.preventDefault();
  });
  // Touch support
  drag.addEventListener("touchstart",e=>{
    startY=e.touches[0].clientY;startH=panel.offsetHeight;
    const onMove=e2=>{
      const h=startH+(startY-e2.touches[0].clientY);
      panel.style.height=Math.max(120,Math.min(window.innerHeight*.85,h))+"px";
      e2.preventDefault();
    };
    const onUp=()=>{document.removeEventListener("touchmove",onMove);document.removeEventListener("touchend",onUp)};
    document.addEventListener("touchmove",onMove,{passive:false});
    document.addEventListener("touchend",onUp);
  },{passive:true});
})();

// Maximize/restore output panel
let _panelMaxed=false;
$("#output-max").onclick=()=>{
  const p=$("#output-panel");
  if(_panelMaxed){p.style.height="var(--panel-h)";_panelMaxed=false}
  else{p.style.height="85vh";_panelMaxed=true}
};

document.addEventListener("click",e=>{
  const el=e.target.closest(".ip-click");
  if(el&&!e.target.closest("tr.clickable")){showCtxMenu(el.dataset.ip,e.clientX,e.clientY);e.stopPropagation();return}
  if(!e.target.closest("#ctx-menu"))$("#ctx-menu").style.display="none";
});

$("#output-close").onclick=()=>{$("#output-panel").classList.remove("open");$("#output-panel").style.height=""};
$("#detail-close").onclick=()=>{$("#detail-panel").classList.remove("open");if(_lastFocus)try{_lastFocus.focus()}catch(e){}};

// Focus trap for detail-panel (modal dialog)
let _lastFocus=null;
function _focusable(el){
  return Array.from(el.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),iframe,[tabindex]:not([tabindex="-1"])'));
}
document.addEventListener("keydown",e=>{
  const dp=$("#detail-panel");
  if(!dp.classList.contains("open")||e.key!=="Tab")return;
  const items=_focusable(dp);
  if(!items.length)return;
  const first=items[0],last=items[items.length-1];
  if(e.shiftKey&&document.activeElement===first){last.focus();e.preventDefault()}
  else if(!e.shiftKey&&document.activeElement===last){first.focus();e.preventDefault()}
});
// Remember last focus when opening modal, restore on close
const _origShowDetail=showHostDetail;
showHostDetail=async function(ip){
  _lastFocus=document.activeElement;
  await _origShowDetail(ip);
  const dp=$("#detail-panel"),first=_focusable(dp)[0];
  if(first)first.focus();
};
const _origShowScan=showScanDetail;
showScanDetail=async function(ip){
  _lastFocus=document.activeElement;
  await _origShowScan(ip);
  const dp=$("#detail-panel"),first=_focusable(dp)[0];
  if(first)first.focus();
};
const _origShowReplay=showReplayDetail;
showReplayDetail=function(sid,proto){
  _lastFocus=document.activeElement;
  _origShowReplay(sid,proto);
  const dp=$("#detail-panel"),first=_focusable(dp)[0];
  if(first)first.focus();
};

$("#cmd-input").addEventListener("keydown",async e=>{
  if(e.key!=="Enter")return;
  const cmd=e.target.value.trim();
  if(!cmd)return;
  e.target.value="";
  runCmd(cmd);
});

function _activateTabIdx(i){
  if(i<0||i>=TABS.length)return;
  tab=TABS[i];
  $$(".tab").forEach((t,j)=>{t.classList.toggle("active",j===i);if(j===i)t.setAttribute("aria-selected","true");else t.setAttribute("aria-selected","false")});
  render();
}
function _tabIdx(name){return TABS.indexOf(name)}
document.addEventListener("keydown",e=>{
  if(document.activeElement===$("#cmd-input"))return;
  if(e.key==="Escape"){
    if($("#kbd-help").classList.contains("open")){$("#kbd-help").classList.remove("open");return}
    if($("#detail-panel").classList.contains("open")){$("#detail-panel").classList.remove("open");return}
    $("#ctx-menu").style.display="none";
    if($("#output-panel").classList.contains("open")){$("#output-panel").classList.remove("open");$("#output-panel").style.height="";return}
    return;
  }
  if(e.key==="?"||(e.key==="/"&&e.shiftKey)){
    e.preventDefault();$("#kbd-help").classList.toggle("open");return;
  }
  if(e.shiftKey){
    if(e.key==="M"||e.key==="m"){const i=_tabIdx("mesh");if(i>=0){e.preventDefault();_activateTabIdx(i);return}}
    if(e.key==="H"||e.key==="h"){const i=_tabIdx("help");if(i>=0){e.preventDefault();_activateTabIdx(i);return}}
    return;
  }
  if(e.key==="r"||e.key==="R"){const i=_tabIdx("replay");if(i>=0){e.preventDefault();_activateTabIdx(i);return}}
  const n=parseInt(e.key);
  if(n>=1&&n<=9&&n<=TABS.length){_activateTabIdx(n-1);return}
  if(e.key==="0"&&TABS.length>=10){_activateTabIdx(9);return}
  if(e.key==="/"){e.preventDefault();$("#cmd-input").focus()}
});

// Theme + Scanline persistence
const _themeSel=$("#theme-sel"),_scanSel=$("#scanline-sel"),_scanOverlay=$("#scanline-overlay");
_themeSel.value=localStorage.getItem("nw_theme")||"";
document.body.className=_themeSel.value;
_scanSel.value=localStorage.getItem("nw_scanline")||"";
_scanOverlay.className=_scanSel.value;
_themeSel.onchange=()=>{
  document.body.className=_themeSel.value;
  localStorage.setItem("nw_theme",_themeSel.value);
  _destroyCharts();
  if(tab==="all"){initCharts();updateCharts();loadTimeseries()}
};
_scanSel.onchange=()=>{_scanOverlay.className=_scanSel.value;localStorage.setItem("nw_scanline",_scanSel.value)};

initTabs();
$("#kbd-help-btn").onclick=()=>$("#kbd-help").classList.toggle("open");
$("#kbd-help").onclick=e=>{if(e.target.id==="kbd-help")$("#kbd-help").classList.remove("open")};
connect();
fetch("/api/state").then(r=>r.json()).then(d=>{D=d;updateHeader();render()}).catch(()=>{});
</script>
</body>
</html>"""

_CAM_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch · Camera Sentry</title>
<style>
 body{background:#0a0e0a;color:#cfe;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:24px}
 h1{color:#7df58a;font-weight:400;letter-spacing:1px;margin:0 0 4px}
 .sub{color:#5a8;margin-bottom:24px;font-size:11px}
 a{color:#7df58a;text-decoration:none}
 a:hover{color:#fff;background:#143}
 .nav{margin-bottom:16px}
 .nav a{padding:4px 10px;border:1px solid #2a4;border-radius:3px;margin-right:8px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
 .cam{background:#0e1810;border:1px solid #143;border-radius:4px;overflow:hidden}
 .cam img{width:100%;display:block;aspect-ratio:16/9;object-fit:cover;background:#000}
 .cam .bar{display:flex;justify-content:space-between;padding:6px 10px;font-size:11px}
 .on{color:#7df58a}.off{color:#f87}
 .empty{padding:40px;text-align:center;color:#588}
 h2{color:#5a8;font-weight:400;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:24px 0 8px}
 ul{list-style:none;padding:0;margin:0}
 li{padding:3px 0;border-bottom:1px solid #0f1a10;color:#9cb;font-size:11px}
</style></head><body>
<div class="nav"><a href="/">&larr; dashboard</a><a href="/cam" id="refresh">&#8635; refresh</a></div>
<h1>CAMERA SENTRY</h1>
<div class="sub">Live feeds — motion + person detection alerts flow into your configured channels</div>
<div id="grid" class="grid"><div class="empty">loading&hellip;</div></div>
<h2>Recent events</h2>
<ul id="events"><li>loading&hellip;</li></ul>
<script>
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let mounted=false;
async function load(){
  let st;
  try{
    const r=await fetch('/api/cam/status');
    if(!r.ok)throw new Error('HTTP '+r.status);
    st=await r.json();
  }catch(e){
    document.getElementById('grid').innerHTML=`<div class="empty">Failed to load status: ${esc(e.message||e)}</div>`;return;
  }
  if(!mounted){
    mounted=true;
    const g=document.getElementById('grid');
    if(!st.cameras.length){g.innerHTML=`<div class="empty">${esc(st.reason||'No cameras configured')} &mdash; add one from the console: <code>cam add blink &lt;name&gt;</code>, <code>cam add rtsp &lt;url&gt;</code> or <code>cam add usb &lt;index&gt;</code></div>`;mounted=false;}
    else g.innerHTML=st.cameras.map(c=>
      `<div class="cam"><img src="/api/cam/stream/${esc(c.id)}" alt="camera ${esc(c.id)}">`+
      `<div class="bar"><span>CAM ${esc(c.id)} &middot; ${esc(c.source)}</span>`+
      `<span id="cs-${esc(c.id)}"></span></div></div>`).join('');
  }
  for(const c of st.cameras){
    const el=document.getElementById('cs-'+c.id);
    if(el)el.innerHTML=(c.online?'<span class="on">&#9679; live</span>':'<span class="off">&#9679; offline</span>')+
      ` &middot; ${esc(c.alerts)} alert${c.alerts===1?'':'s'}`;
  }
  document.getElementById('events').innerHTML=
    (st.events&&st.events.length?st.events.slice().reverse().map(e=>`<li>${esc(e)}</li>`).join(''):'<li>none yet</li>');
}
load();setInterval(load,5000);
</script></body></html>"""

_REPLAY_INDEX_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch · Replay sessions</title>
<style>
 body{background:#0a0e0a;color:#cfe;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:24px}
 h1{color:#7df58a;font-weight:400;letter-spacing:1px;margin:0 0 4px}
 .sub{color:#5a8;margin-bottom:24px;font-size:11px}
 a{color:#7df58a;text-decoration:none}
 a:hover{color:#fff;background:#143}
 table{width:100%;border-collapse:collapse;margin-top:8px}
 th{text-align:left;padding:6px 10px;color:#5a8;font-weight:400;border-bottom:1px solid #143;font-size:11px;text-transform:uppercase;letter-spacing:1px}
 td{padding:6px 10px;border-bottom:1px solid #0f1a10}
 tr:hover td{background:#0e1810}
 .empty{padding:40px;text-align:center;color:#588}
 .nav{margin-bottom:16px}
 .nav a{padding:4px 10px;border:1px solid #2a4;border-radius:3px;margin-right:8px}
 .ip{color:#fff}
 .num{color:#999;text-align:right}
 .proto{font-size:10px;padding:1px 6px;border-radius:2px;text-transform:uppercase;letter-spacing:1px}
 .proto.ftp{background:#143;color:#7df58a}
 .proto.telnet{background:#311;color:#f87}
</style></head><body>
<div class="nav"><a href="/">← dashboard</a><a href="/replay" id="refresh">↻ refresh</a></div>
<h1>SESSION REPLAY</h1>
<div class="sub">Captured honeypot sessions — click any session to scrub the timeline</div>
<div id="content"><div class="empty">loading…</div></div>
<script>
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load(){
  let sessions;
  try{
    const r=await fetch('/api/replay');
    if(!r.ok)throw new Error('HTTP '+r.status);
    sessions=await r.json();
  }catch(e){
    document.getElementById('content').innerHTML=`<div class="empty">Failed to load sessions: ${esc(e.message||e)}</div>`;return;
  }
  const el=document.getElementById('content');
  if(!sessions.length){el.innerHTML='<div class="empty">No sessions captured yet — once attackers hit a honeypot, they\'ll appear here.</div>';return}
  let h='<table><thead><tr><th>session id</th><th>proto</th><th>attacker ip</th><th>captured</th><th>events</th></tr></thead><tbody>';
  for(const s of sessions){
    const ts=String(s.started_at_mtime||'').replace('T',' ').replace(/\..*/,'');
    const proto=(s.protocol==='telnet')?'telnet':'ftp';  // whitelist
    const sid=encodeURIComponent(s.session_id);
    h+=`<tr><td><a href="/replay/${sid}?proto=${proto}">${esc(s.session_id)}</a></td>`+
       `<td><span class="proto ${proto}">${proto}</span></td>`+
       `<td class="ip">${esc(s.ip)}</td><td>${esc(ts)} UTC</td><td class="num">${Number(s.event_count)||0}</td></tr>`;
  }
  el.innerHTML=h+'</tbody></table>';
}
load();
document.getElementById('refresh').addEventListener('click',e=>{e.preventDefault();load()});
</script>
</body></html>"""

_REPLAY_PLAYER_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch · Replay {{ session_id }}</title>
<style>
 body{background:#0a0e0a;color:#cfe;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:0}
 header{padding:14px 20px;border-bottom:1px solid #143;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
 header h1{color:#7df58a;font:400 14px/1 inherit;letter-spacing:2px;margin:0}
 header .meta{color:#5a8;font-size:11px}
 header .meta b{color:#fff;font-weight:400}
 header a{color:#7df58a;text-decoration:none;padding:3px 8px;border:1px solid #2a4;border-radius:3px;font-size:11px}
 main{display:grid;grid-template-columns:1fr 280px;height:calc(100vh - 130px)}
 #events{overflow-y:auto;padding:12px 18px}
 .ev{padding:3px 0;display:grid;grid-template-columns:70px 80px 1fr;gap:10px;border-radius:2px}
 .ev .t{color:#588;font-size:11px}
 .ev .k{font-size:11px;text-transform:uppercase;letter-spacing:1px}
 .ev[data-k=server] .k{color:#7df58a}
 .ev[data-k=server_fail] .k{color:#f55}
 .ev[data-k=client] .k{color:#fc7}
 .ev[data-k=cred] .k{color:#f9f}
 .ev[data-k=upload] .k,.ev[data-k=upload_saved] .k,.ev[data-k=data_recv] .k{color:#9cf}
 .ev[data-k=download] .k,.ev[data-k=data_send] .k{color:#9cf}
 .ev[data-k=session_end] .k,.ev[data-k=quit] .k{color:#666}
 .ev .x{color:#cfe;word-break:break-all;white-space:pre-wrap}
 .ev.future{opacity:.18}
 .ev.cursor{background:#143}
 #intel{border-left:1px solid #143;padding:14px 16px;overflow-y:auto;background:#070b07}
 #intel h2{color:#5a8;font:400 11px/1 inherit;letter-spacing:2px;text-transform:uppercase;margin:0 0 12px}
 #intel dt{color:#588;font-size:11px;margin-top:10px;text-transform:uppercase;letter-spacing:1px}
 #intel dd{color:#fff;margin:2px 0 0}
 #intel .empty{color:#588;font-style:italic;font-size:11px}
 footer{border-top:1px solid #143;padding:10px 18px;display:flex;align-items:center;gap:14px;background:#070b07}
 footer button{background:#0a0e0a;color:#7df58a;border:1px solid #2a4;padding:4px 12px;border-radius:3px;cursor:pointer;font:inherit}
 footer button:hover{background:#143;color:#fff}
 footer button.active{background:#143;color:#fff}
 #scrub{flex:1;height:6px;-webkit-appearance:none;background:#143;border-radius:3px;outline:none}
 #scrub::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;background:#7df58a;border-radius:50%;cursor:pointer}
 #scrub::-moz-range-thumb{width:14px;height:14px;background:#7df58a;border-radius:50%;border:none;cursor:pointer}
 #time{color:#fff;font-variant-numeric:tabular-nums;min-width:120px;text-align:right}
 .err{color:#f55;padding:40px;text-align:center}
</style></head><body>
<header>
 <h1>NETWATCH · REPLAY</h1>
 <div class="meta">session <b id="sid">{{ session_id }}</b></div>
 <div class="meta">ip <b id="ip">…</b></div>
 <div class="meta">duration <b id="dur">…</b></div>
 <a href="/replay">← all sessions</a>
</header>
<main>
 <div id="events"><div class="err">loading…</div></div>
 <div id="intel"><h2>ATTACKER INTEL</h2><div id="intelBody"><div class="empty">loading…</div></div></div>
</main>
<footer>
 <button id="home" title="jump to start (Home)">⏮</button>
 <button id="back10" title="-10s (&lt;)">⏪</button>
 <button id="back1" title="-1s (←)">◀</button>
 <button id="play">▶</button>
 <button id="fwd1" title="+1s (→)">▶|</button>
 <button id="fwd10" title="+10s (&gt;)">⏩</button>
 <button id="end" title="jump to end (End)">⏭</button>
 <button data-speed="0.5">0.5×</button>
 <button data-speed="1" class="active">1×</button>
 <button data-speed="2">2×</button>
 <button data-speed="4">4×</button>
 <input type="range" id="scrub" min="0" max="0" value="0" step="1">
 <span id="time">00:00 / 00:00</span>
</footer>
<script>
const sid={{ session_id|tojson }};
const proto={{ protocol|tojson }};
const SPEEDS=[0.25,0.5,1,2,4,8];
let timeline=null,cursor=0,playing=false,speed=1,timer=null,lastTick=0;
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function fmt(ms){const s=Math.floor(ms/1000),m=Math.floor(s/60);return `${String(m).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`}
function renderIntel(intel){
 const b=document.getElementById('intelBody');
 if(!intel||!intel.ip){b.innerHTML='<div class="empty">No OSINT recon yet for this IP. Run <code>recon</code> from the dashboard.</div>';return}
 const rows=[['IP',intel.ip],['Country',intel.country],['City',intel.city],['ASN',intel.asn],['Org',intel.org],['Abuse',intel.abuse_score],['Hostname',intel.hostname]];
 let h='<dl>';
 for(const [k,v] of rows)if(v||v===0)h+=`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`;
 if(intel.tags&&intel.tags.length)h+=`<dt>Tags</dt><dd>${esc(intel.tags.join(', '))}</dd>`;
 if(intel.notes)h+=`<dt>Notes</dt><dd>${esc(intel.notes)}</dd>`;
 b.innerHTML=h+'</dl>';
}
function renderEvents(){
 const el=document.getElementById('events');
 if(!timeline.events.length){el.innerHTML='<div class="err">No events captured in this session (banner-only).</div>';return}
 let h='',lastCursorIdx=-1;
 for(let i=0;i<timeline.events.length;i++){
  const e=timeline.events[i],fut=e.t_ms>cursor;
  if(!fut)lastCursorIdx=i;
  h+=`<div class="ev${fut?' future':''}" data-k="${esc(e.kind)}" data-i="${i}"><span class="t">${fmt(e.t_ms)}</span><span class="k">${esc(e.kind)}</span><span class="x">${esc(e.text)}</span></div>`;
 }
 el.innerHTML=h;
 const cur=el.querySelector(`[data-i="${lastCursorIdx}"]`);
 if(cur){cur.classList.add('cursor');cur.scrollIntoView({block:'nearest'})}
}
function updateScrubber(){
 document.getElementById('scrub').value=cursor;
 document.getElementById('time').textContent=`${fmt(cursor)} / ${fmt(timeline.duration_ms)}`;
}
function setCursor(ms){
 cursor=Math.max(0,Math.min(timeline.duration_ms,ms|0));
 lastTick=performance.now();
 updateScrubber();renderEvents();
}
function setSpeed(v){
 speed=v;lastTick=performance.now();
 document.querySelectorAll('[data-speed]').forEach(x=>x.classList.toggle('active',parseFloat(x.dataset.speed)===v));
}
function stepSpeed(dir){
 const i=SPEEDS.indexOf(speed);
 const ni=Math.max(0,Math.min(SPEEDS.length-1,(i<0?2:i)+dir));
 setSpeed(SPEEDS[ni]);
}
function play(){
 if(!playing && cursor>=timeline.duration_ms) cursor=0;  // restart from end
 playing=!playing;
 document.getElementById('play').textContent=playing?'❚❚':'▶';
 lastTick=performance.now();
 if(playing&&!timer)tick();
}
function tick(){
 if(!playing){timer=null;return}
 const now=performance.now(),dt=(now-lastTick)*speed;lastTick=now;
 cursor=Math.min(timeline.duration_ms,cursor+dt);
 updateScrubber();renderEvents();
 if(cursor>=timeline.duration_ms){playing=false;document.getElementById('play').textContent='▶';timer=null;return}
 timer=requestAnimationFrame(tick);
}
async function load(){
 try{
  const r=await fetch(`/api/replay/${encodeURIComponent(sid)}?proto=${proto}`);
  if(!r.ok){document.getElementById('events').innerHTML=`<div class="err">${esc((await r.json()).error||'load failed')}</div>`;return}
  timeline=await r.json();
  document.getElementById('ip').textContent=timeline.ip;
  document.getElementById('dur').textContent=fmt(timeline.duration_ms);
  document.getElementById('scrub').max=Math.max(timeline.duration_ms,1);
  // Auto-slow sub-2-second captures so playback is actually visible
  // (many FTP probes are sub-100ms TLS handshakes that would flash past).
  if(timeline.duration_ms>0 && timeline.duration_ms<2000){
    setSpeed(0.25);
    document.getElementById('dur').title='Auto-slowed to 0.25× — session is under 2s';
  }
  renderIntel(timeline.intel);renderEvents();updateScrubber();
 }catch(e){document.getElementById('events').innerHTML=`<div class="err">${esc(e)}</div>`}
}
document.getElementById('play').addEventListener('click',play);
document.getElementById('back1').addEventListener('click',()=>setCursor(cursor-1000));
document.getElementById('fwd1').addEventListener('click',()=>setCursor(cursor+1000));
document.getElementById('back10').addEventListener('click',()=>setCursor(cursor-10000));
document.getElementById('fwd10').addEventListener('click',()=>setCursor(cursor+10000));
document.getElementById('home').addEventListener('click',()=>setCursor(0));
document.getElementById('end').addEventListener('click',()=>setCursor(timeline?timeline.duration_ms:0));
document.getElementById('scrub').addEventListener('input',e=>setCursor(parseInt(e.target.value,10)));
document.querySelectorAll('[data-speed]').forEach(b=>b.addEventListener('click',()=>setSpeed(parseFloat(b.dataset.speed))));
document.addEventListener('keydown',e=>{
 if(!timeline)return;
 const tag=(e.target.tagName||'').toLowerCase();
 if(tag==='input'||tag==='textarea')return;
 switch(e.key){
  case ' ':e.preventDefault();play();break;
  case 'ArrowLeft':e.preventDefault();setCursor(cursor-1000);break;
  case 'ArrowRight':e.preventDefault();setCursor(cursor+1000);break;
  case '<':case ',':e.preventDefault();setCursor(cursor-10000);break;
  case '>':case '.':e.preventDefault();setCursor(cursor+10000);break;
  case 'Home':e.preventDefault();setCursor(0);break;
  case 'End':e.preventDefault();setCursor(timeline.duration_ms);break;
  case '+':case '=':e.preventDefault();stepSpeed(1);break;
  case '-':case '_':e.preventDefault();stepSpeed(-1);break;
 }
});
load();
</script>
</body></html>"""
