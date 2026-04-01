const $ = id => document.getElementById(id);
const urlInput      = $("urlInput");
const scanBtn       = $("scanBtn");
const clearBtn      = $("clearBtn");
const randomBtn     = $("randomBtn");
const pasteBtn      = $("pasteBtn");
const themeToggle   = $("themeToggle");
const progressFill  = $("progressFill");
const progressPct   = $("progressPercent");
const statusPill    = $("statusPill");
const resultTitle   = $("resultTitle");
const resultSub     = $("resultSubtitle");
const riskValue     = $("riskValue");
const scoreCircle   = $("scoreCircle");
const protocolRes   = $("protocolResult");
const domainRes     = $("domainResult");
const entropyRes    = $("entropyResult");
const brandRes      = $("brandResult");
const reasonList    = $("reasonList");
const fieldNote     = $("fieldNote");
const historyList   = $("historyList");
const copyReportBtn = $("copyReportBtn");
const threatTagsEl  = $("threatTags");
const safeVerified  = $("safeVerified");
const confFill      = $("confFill");
const confLabel     = $("confidenceLabel");
const apiResultRows = $("apiResultRows");
const exportTxtBtn  = $("exportTxtBtn");
const exportJsonBtn = $("exportJsonBtn");
const gsbKeyInput   = $("gsbKey");
const vtKeyInput    = $("vtKey");
const gsbStatusEl   = $("gsbStatus");
const vtStatusEl    = $("vtStatus");
const batchInput    = $("batchInput");
const batchResults  = $("batchResults");

const metricLength   = $("metricLength");
const metricSpecial  = $("metricSpecial");
const metricKeyword  = $("metricKeyword");
const metricSubdomain= $("metricSubdomain");
const metricEntropy  = $("metricEntropy");
const metricEncoding = $("metricEncoding");

const barLength   = $("barLength");
const barSpecial  = $("barSpecial");
const barKeyword  = $("barKeyword");
const barSubdomain= $("barSubdomain");
const barEntropy  = $("barEntropy");
const barEncoding = $("barEncoding");

let latestReport     = null;  
let scanHistory      = [];


const RISK_PHISHING   = 70;
const RISK_SUSPICIOUS = 40;

const WHITELIST = new Set([
  "google.com","youtube.com","facebook.com","instagram.com","twitter.com","x.com",
  "linkedin.com","microsoft.com","apple.com","amazon.com","netflix.com","github.com",
  "stackoverflow.com","reddit.com","wikipedia.org","cloudflare.com","mozilla.org",
  "openai.com","anthropic.com","stripe.com","dropbox.com","spotify.com","adobe.com",
  "salesforce.com","zoom.us","paypal.com","ebay.com","walmart.com","target.com",
  "chase.com","wellsfargo.com","bankofamerica.com","yahoo.com","bing.com","live.com",
  "outlook.com","office.com","azure.com","aws.amazon.com","gitlab.com","bitbucket.org",
]);

const BRANDS = [
  { name:"paypal",      legit:["paypal.com"] },
  { name:"apple",       legit:["apple.com","icloud.com","itunes.com"] },
  { name:"amazon",      legit:["amazon.com","amazon.co.uk","amazon.in","amazon.de","aws.amazon.com"] },
  { name:"google",      legit:["google.com","googleapis.com","googleusercontent.com","gstatic.com","gmail.com"] },
  { name:"microsoft",   legit:["microsoft.com","microsoftonline.com","azure.com","office.com","live.com","outlook.com","bing.com"] },
  { name:"netflix",     legit:["netflix.com"] },
  { name:"facebook",    legit:["facebook.com","fb.com","fbcdn.net","messenger.com"] },
  { name:"instagram",   legit:["instagram.com","cdninstagram.com"] },
  { name:"twitter",     legit:["twitter.com","x.com","t.co","twimg.com"] },
  { name:"linkedin",    legit:["linkedin.com","licdn.com"] },
  { name:"chase",       legit:["chase.com","jpmorganchase.com"] },
  { name:"wellsfargo",  legit:["wellsfargo.com","wachovia.com"] },
  { name:"citibank",    legit:["citibank.com","citi.com"] },
  { name:"hsbc",        legit:["hsbc.com","hsbc.co.uk"] },
  { name:"dropbox",     legit:["dropbox.com","dropboxusercontent.com"] },
  { name:"spotify",     legit:["spotify.com","scdn.co"] },
  { name:"adobe",       legit:["adobe.com","adobecc.com"] },
  { name:"stripe",      legit:["stripe.com","stripe.network"] },
  { name:"zoom",        legit:["zoom.us","zoom.com"] },
  { name:"ebay",        legit:["ebay.com","ebay.co.uk"] },
  { name:"walmart",     legit:["walmart.com"] },
  { name:"dhl",         legit:["dhl.com","dhl.de"] },
  { name:"fedex",       legit:["fedex.com"] },
  { name:"ups",         legit:["ups.com"] },
];

const TRUSTED_FOR_TYPO = [
  "google.com","facebook.com","amazon.com","microsoft.com","apple.com",
  "paypal.com","twitter.com","instagram.com","netflix.com","linkedin.com",
  "youtube.com","github.com","dropbox.com","spotify.com","adobe.com",
  "yahoo.com","gmail.com","outlook.com","ebay.com","walmart.com",
];

const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","rb.gy",
  "cutt.ly","short.io","is.gd","v.gd","tiny.cc","shorturl.at","tr.im",
  "po.st","lnkd.in","mcaf.ee","j.mp","tiny.one","clck.ru","qr.ae",
  "adf.ly","bc.vc","surl.li","soo.gd","gg.gg",
]);

const RISKY_TLDS = new Set([
  "xyz","top","info","click","buzz","shop","live","rest","gq","country",
  "work","party","download","stream","loan","review","win","accountant",
  "science","date","faith","racing","icu","monster","cyou","bond","cfd",
  "sbs","lol","vip","pw","cf","tk","ml","ga","co.vu","to",
]);

const SUSPICIOUS_KEYWORDS = [
  "login","verify","secure","update","bank","account","signin","wallet",
  "payment","confirm","password","billing","recover","reset","unlock",
  "validate","suspend","credential","authenticate","reactivate","urgent",
  "alert","notice","invoice","refund","claim","prize","winner","free",
  "offer","limited","expire","activity","suspicious","breach",
];

const LURE_PREFIXES = [
  "secure","login","verify","update","account","banking","myaccount",
  "weblogin","auth","portal","signin","service","support","help","online",
];

const REDIRECT_PARAMS = [
  "redirect=","url=","goto=","next=","return=","returnUrl=","forward=",
  "dest=","destination=","go=","jump=","link=","out=","target=",
];

const DEMO_URLS = [
  "https://google.com",
  "https://github.com",
  "http://secure-login-paypal-update.xyz",
  "http://192.168.0.10/account/verify",
  "https://microsoft.com",
  "http://banking-alert-confirm-user.info/login",
  "https://paypa1-secure.verify-account.info/login?redirect=http://evil.com",
  "https://bit.ly/3xyz4ab",
  "http://amazon-security-alert.xyz/account/verify?token=abc123%2Fdef",
  "https://netfl1x-billing-update.com/account",
];


function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const n = str.length;
  return -Object.values(freq).reduce((s, f) => {
    const p = f / n;
    return s + p * Math.log2(p);
  }, 0);
}


function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({length: m + 1}, (_, i) =>
    Array.from({length: n + 1}, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}


function normalizeURL(url) {
  const t = url.trim();
  if (!t) return "";
  return /^https?:\/\//i.test(t) ? t : "https://" + t;
}

function isIPAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function getBaseDomain(hostname) {
  const parts = hostname.replace(/^www\./, "").split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}


function evaluateURL(inputURL) {
  const normalized = normalizeURL(inputURL);
  let parsed;
  try { parsed = new URL(normalized); }
  catch { return { valid: false, message: "Invalid URL format. Please enter a valid web address." }; }

  const hostname  = parsed.hostname.toLowerCase();
  const pathname  = parsed.pathname.toLowerCase();
  const search    = parsed.search.toLowerCase();
  const full      = normalized.toLowerCase();
  const tld       = hostname.split(".").pop();
  const baseDomain= getBaseDomain(hostname);
  const firstLabel= hostname.split(".")[0];
  const dotCount  = (hostname.match(/\./g) || []).length;
  const subCount  = Math.max(0, dotCount - 1);

  let risk = 0;
  const reasons = [];      
  const threats = [];      

  const r = (score, text, type) => { risk += score; reasons.push({text, type}); };
  const flag = t => threats.push(t);

  
  const isWhitelisted = WHITELIST.has(baseDomain) || WHITELIST.has(hostname.replace(/^www\./, ""));
  if (isWhitelisted) {
    risk -= 30;
    reasons.push({ text: "Domain matches a known trusted website (whitelist).", type: "positive" });
  }

  
  if (parsed.protocol !== "https:") {
    r(18, "Connection uses HTTP — traffic is unencrypted and may be intercepted.", "danger");
    flag("NO HTTPS");
  } else {
    reasons.push({ text: "HTTPS is present — connection is encrypted.", type: "positive" });
  }

 
  if (isIPAddress(hostname)) {
    r(24, "Domain is a raw IP address — legitimate websites rarely use these.", "danger");
    flag("IP HOST");
  }

  
  if (SHORTENERS.has(hostname)) {
    r(20, "This is a URL shortener — the real destination is hidden and unverifiable.", "danger");
    flag("URL SHORTENER");
  }

  
  const urlLen = full.length;
  const lengthRisk = Math.min((urlLen / 120) * 100, 100);
  if (urlLen > 100) {
    r(16, `Very long URL (${urlLen} chars) — commonly used to bury the real domain.`, "danger");
  } else if (urlLen > 60) {
    r(8, `Moderately long URL (${urlLen} chars).`, "warning");
  }

  
  const specialCount = (full.match(/[@_\-=%]/g) || []).length;
  const specialRisk  = Math.min((specialCount / 8) * 100, 100);
  if (specialCount >= 4) {
    r(14, `${specialCount} special characters in URL — typical obfuscation pattern.`, "danger");
  } else if (specialCount >= 1) {
    r(5, "URL contains special characters that may mask the true destination.", "warning");
  }

  
  const subdomainRisk = Math.min((subCount / 4) * 100, 100);
  if (subCount >= 3) {
    r(16, `${subCount} subdomains detected — a classic tactic to bury a malicious domain.`, "danger");
  } else if (subCount === 2) {
    r(8, "Multiple subdomains present — check that the root domain is legitimate.", "warning");
  }

  
  let kwHits = 0;
  const foundKW = [];
  SUSPICIOUS_KEYWORDS.forEach(kw => { if (full.includes(kw)) { kwHits++; foundKW.push(kw); }});
  const keywordRisk = Math.min(kwHits * 20, 100);
  if (kwHits >= 3) {
    r(24, `Multiple phishing keywords found: ${foundKW.slice(0,5).join(", ")}.`, "danger");
    flag("KEYWORD ABUSE");
  } else if (kwHits >= 1) {
    r(10, `Suspicious keyword "${foundKW[0]}" in URL — common in phishing lures.`, "warning");
  }

 
  if (RISKY_TLDS.has(tld)) {
    r(10, `.${tld} is a TLD frequently used for phishing and spam domains.`, "warning");
  }

  
  if (!isWhitelisted && LURE_PREFIXES.some(p => firstLabel.startsWith(p))) {
    r(10, `Domain starts with "${firstLabel}" — a security-related lure word.`, "warning");
  }

 
  if (!isWhitelisted && hostname.includes("-")) {
    const hc = (hostname.match(/-/g) || []).length;
    r(Math.min(hc * 5, 15), `Domain contains ${hc} hyphen(s) — often used to mimic trusted brands.`, "warning");
  }

 
  if (full.includes("@")) {
    r(22, 'URL contains "@" — browsers ignore everything before it; this tricks users about the real host.', "danger");
    flag("@ TRICK");
  }

  
  const hasRedirect = REDIRECT_PARAMS.some(p => full.includes(p));
  if (hasRedirect) {
    r(12, "URL contains a redirect parameter — may route through a trusted domain to a malicious one.", "warning");
    flag("OPEN REDIRECT");
  }

  
  const encCount = (full.match(/%[0-9a-f]{2}/gi) || []).length;
  const encodingRisk = Math.min((encCount / 5) * 100, 100);
  if (encCount >= 4) {
    r(14, `${encCount} percent-encoded characters — obfuscation technique used to bypass filters.`, "danger");
    flag("ENCODING");
  } else if (encCount >= 1) {
    r(5, "Encoded characters in URL may conceal its true purpose.", "warning");
  }

  
  if (parsed.port && !["80","443",""].includes(parsed.port)) {
    r(14, `Non-standard port ${parsed.port} — legitimate websites rarely use custom ports.`, "danger");
    flag("ODD PORT");
  }

  
  const entropy = shannonEntropy(baseDomain.replace(/\./g,""));
  const entropyRisk = Math.min((entropy / 5) * 100, 100);
  if (!isWhitelisted && entropy > 4.0) {
    r(12, `High domain entropy (${entropy.toFixed(2)}) — possibly algorithmically generated (DGA).`, "warning");
    flag("HIGH ENTROPY");
  } else if (!isWhitelisted && entropy > 3.2) {
    r(5, `Moderate domain entropy (${entropy.toFixed(2)}) — slightly random-looking domain.`, "info");
  }

  
  let impersonated = null;
  for (const brand of BRANDS) {
    if (hostname.includes(brand.name)) {
      const legit = brand.legit.some(d => hostname === d || hostname === "www." + d || hostname.endsWith("." + d));
      if (!legit) {
        impersonated = brand.name;
        r(28, `URL impersonates "${brand.name}" using a different domain — HIGH brand spoof risk!`, "danger");
        flag("BRAND SPOOF");
        break;
      }
    }
  }

  
  if (!impersonated && !isWhitelisted) {
    let best = null, bestDist = Infinity;
    for (const td of TRUSTED_FOR_TYPO) {
      const d = levenshtein(baseDomain, td);
      if (d > 0 && d <= 2 && d < bestDist) { bestDist = d; best = td; }
    }
    if (best) {
      r(20, `Domain differs from "${best}" by only ${bestDist} character(s) — possible typosquatting attack.`, "danger");
      flag("TYPOSQUATTING");
    }
  }

  
  if (/[^\x00-\x7F]/.test(parsed.hostname)) {
    r(20, "Domain contains non-ASCII characters — visual impersonation via look-alike letters.", "danger");
    flag("HOMOGLYPH");
  }

 
  if (hostname.includes("xn--")) {
    r(15, "Domain uses Punycode (xn--) — internationalized domain that may visually mimic another.", "warning");
    flag("PUNYCODE");
  }

 
  const pathExts = (pathname.match(/\.[a-z]{2,5}/g) || []);
  if (pathExts.length >= 2) {
    r(8, "Multiple file extensions in path — may deceive about the actual file type.", "warning");
  }

 
  const slashCount = (pathname.match(/\//g) || []).length;
  if (slashCount >= 5) {
    r(6, "Deeply nested URL path — can be used to obscure the real domain.", "warning");
  }

  
  if (!isWhitelisted && firstLabel.length > 25) {
    r(6, `Primary domain label is ${firstLabel.length} characters long — unusually long.`, "warning");
  }

  
  risk = Math.max(0, Math.min(risk, 100));

  let status = "Safe", typeClass = "safe";
  let subtitle = "No major threats detected. URL appears low-risk based on 23-point heuristic analysis.";
  if (risk >= RISK_PHISHING) {
    status = "Phishing"; typeClass = "danger";
    subtitle = "Multiple high-risk indicators found. This URL is likely malicious — do not visit.";
  } else if (risk >= RISK_SUSPICIOUS) {
    status = "Suspicious"; typeClass = "warn";
    subtitle = "Several warning signals found. Proceed with extreme caution.";
  }

  
  const totalSigs = reasons.length;
  const confidence = Math.min(45 + totalSigs * 4 + (risk > 60 ? 15 : risk > 30 ? 8 : 0), 97);

  return {
    valid: true, normalized, hostname, baseDomain, risk, status, typeClass, subtitle,
    reasons, threats, isWhitelisted, impersonated, entropy,
    confidence,
    metrics: {
      length:   Math.round(lengthRisk),
      special:  Math.round(specialRisk),
      keyword:  Math.round(keywordRisk),
      subdomain:Math.round(subdomainRisk),
      entropy:  Math.round(entropyRisk),
      encoding: Math.round(encodingRisk),
    },
    protocol:   parsed.protocol === "https:" ? "HTTPS ✓ Encrypted" : "HTTP ✗ Unencrypted",
    domainStyle: isIPAddress(hostname)    ? "Raw IP address"
               : SHORTENERS.has(hostname) ? "URL Shortener"
               : subCount >= 3            ? "Complex multi-subdomain"
               : hostname.includes("-")   ? "Hyphenated domain"
               : isWhitelisted            ? "Known trusted domain"
               :                           "Standard domain pattern",
  };
}


async function checkGSB(url, apiKey) {
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "phishguard-ai", clientVersion: "2.0" },
          threatInfo: {
            threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
      }
    );
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e?.error?.message || `HTTP ${res.status}`);
    }
    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      return { ok: true, flagged: true, threats: data.matches.map(m => m.threatType) };
    }
    return { ok: true, flagged: false };
  } catch(err) {
    return { ok: false, error: err.message };
  }
}


async function checkVT(url, apiKey) {
  try {
    const urlId = btoa(url).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey },
    });
    if (res.status === 404) {
    
      const fd = new FormData();
      fd.append("url", url);
      await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST", headers: { "x-apikey": apiKey }, body: fd,
      });
      return { ok: true, pending: true };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const mal  = stats.malicious  || 0;
    const susp = stats.suspicious || 0;
    const total= Object.values(stats).reduce((a,b) => a+b, 0);
    return { ok: true, pending: false, flagged: mal > 0, malicious: mal, suspicious: susp, total };
  } catch(err) {
    return { ok: false, error: err.message };
  }
}


function setProgress(pct) {
  progressFill.style.width = pct + "%";
  progressPct.textContent  = pct + "%";
}

function setBar(el, val) {
  el.style.width = Math.max(0, Math.min(val, 100)) + "%";
  el.style.background = val >= 70 ? "var(--danger)"
                      : val >= 40 ? "var(--warning)"
                      :             "var(--accent)";
}

function setPill(el, state, text) {
  el.className = "api-pill " + state;
  el.textContent = text;
}

function stageSet(id, cls) {
  const el = $(id);
  if (el) { el.className = "stage-chip " + cls; }
}

async function stageActivate(id, delay = 260) {
  stageSet(id, "active");
  await sleep(delay);
}

async function stageDone(id) { stageSet(id, "done"); }

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function resetStages() {
  ["stg1","stg2","stg3","stg4","stg5","stg6"].forEach(s => stageSet(s, ""));
}

function buildReasons(reasons) {
  reasonList.innerHTML = reasons.map(r => {
    const cls = r.type === "danger"   ? "rl-danger"
              : r.type === "warning"  ? "rl-warning"
              : r.type === "positive" ? "rl-positive"
              :                         "rl-info";
    return `<li class="${cls}">${r.text}</li>`;
  }).join("");
}

function buildThreatTags(threats, typeClass) {
  if (threats.length === 0) {
    threatTagsEl.innerHTML = typeClass === "safe"
      ? `<span class="ttag green">✓ NO THREATS</span>`
      : "";
    return;
  }
  const colorMap = { danger:"red", warn:"orange", safe:"green" };
  const col = colorMap[typeClass] || "orange";
  threatTagsEl.innerHTML = threats.map(t => `<span class="ttag ${col}">${t}</span>`).join("");
}

function buildApiResultRows(gsbResult, vtResult) {
  let html = "";
  if (gsbResult) {
    const val = !gsbResult.ok
      ? `<span style="color:var(--warning)">Error: ${gsbResult.error}</span>`
      : gsbResult.flagged
      ? `<span style="color:var(--danger)">⚠ Flagged: ${gsbResult.threats.join(", ")}</span>`
      : `<span style="color:var(--safe)">✓ Clean</span>`;
    html += `<div class="api-result-row"><span class="arl">Google Safe Browsing</span><span class="arv">${val}</span></div>`;
  }
  if (vtResult) {
    let val;
    if (!vtResult.ok) val = `<span style="color:var(--warning)">Error: ${vtResult.error}</span>`;
    else if (vtResult.pending) val = `<span style="color:var(--primary)">Submitted for analysis</span>`;
    else if (vtResult.flagged) val = `<span style="color:var(--danger)">⚠ ${vtResult.malicious}/${vtResult.total} engines flagged</span>`;
    else val = `<span style="color:var(--safe)">✓ Clean (${vtResult.total} engines)</span>`;
    html += `<div class="api-result-row"><span class="arl">VirusTotal</span><span class="arv">${val}</span></div>`;
  }
  apiResultRows.innerHTML = html;
}

function resetUI() {
  setProgress(0); resetStages();
  statusPill.className = "status-pill neutral";
  statusPill.textContent = "Awaiting Scan";
  resultTitle.textContent = "No result yet";
  resultSub.textContent   = "Submit a URL to view scan output and explainable reasons.";
  riskValue.textContent   = "0%";
  scoreCircle.style.setProperty("--score", 0);
  protocolRes.textContent = "—";
  domainRes.textContent   = "—";
  entropyRes.textContent  = "—";
  brandRes.textContent    = "—";
  safeVerified.innerHTML  = "";
  threatTagsEl.innerHTML  = "";
  apiResultRows.innerHTML = "";
  confFill.style.width    = "0%";
  confLabel.textContent   = "—";
  reasonList.innerHTML    = "<li>No analysis yet.</li>";
  fieldNote.textContent   = "Tip: Enter full URL with http:// or https:// for best results.";
  latestReport = null;
  exportTxtBtn.disabled = exportJsonBtn.disabled = true;
  ["metricLength","metricSpecial","metricKeyword","metricSubdomain","metricEntropy","metricEncoding"]
    .forEach(id => $(id).textContent = "0");
  [barLength,barSpecial,barKeyword,barSubdomain,barEntropy,barEncoding]
    .forEach(el => { el.style.width = "0%"; });
}

function renderResults(ev, gsbRes, vtRes) {
  statusPill.className = `status-pill ${ev.typeClass}`;
  statusPill.textContent = ev.status;
  resultTitle.textContent = ev.status + " Website";
  resultSub.textContent   = ev.subtitle;
  riskValue.textContent   = ev.risk + "%";
  scoreCircle.style.setProperty("--score", ev.risk);
  protocolRes.textContent = ev.protocol;
  domainRes.textContent   = ev.domainStyle;
  entropyRes.textContent  = ev.entropy.toFixed(2) + " bits";
  brandRes.textContent    = ev.impersonated ? "⚠ " + ev.impersonated.toUpperCase() : "None detected";
  if (ev.impersonated) brandRes.style.color = "var(--danger)";
  else brandRes.style.color = "";

  safeVerified.innerHTML = ev.isWhitelisted
    ? `<span class="safe-verified">✓ Verified Trusted Domain</span>` : "";

  buildThreatTags(ev.threats, ev.typeClass);
  buildReasons(ev.reasons);
  buildApiResultRows(gsbRes, vtRes);

  confFill.style.width  = ev.confidence + "%";
  confLabel.textContent = ev.confidence + "%";

  metricLength.textContent   = ev.metrics.length;
  metricSpecial.textContent  = ev.metrics.special;
  metricKeyword.textContent  = ev.metrics.keyword;
  metricSubdomain.textContent= ev.metrics.subdomain;
  metricEntropy.textContent  = ev.metrics.entropy;
  metricEncoding.textContent = ev.metrics.encoding;

  setBar(barLength,    ev.metrics.length);
  setBar(barSpecial,   ev.metrics.special);
  setBar(barKeyword,   ev.metrics.keyword);
  setBar(barSubdomain, ev.metrics.subdomain);
  setBar(barEntropy,   ev.metrics.entropy);
  setBar(barEncoding,  ev.metrics.encoding);
}

function addToHistory(ev) {
  scanHistory.unshift({
    url: ev.normalized, status: ev.status, risk: ev.risk,
    typeClass: ev.typeClass, time: new Date().toLocaleString(),
  });
  scanHistory = scanHistory.slice(0, 8);
  updateHistory();
}

function updateHistory() {
  if (scanHistory.length === 0) {
    historyList.innerHTML = '<div class="history-empty">No scans yet.</div>';
    return;
  }
  historyList.innerHTML = scanHistory.map((item, idx) => `
    <div class="history-item" data-idx="${idx}">
      <div class="history-top">
        <span class="history-badge ${item.typeClass}">${item.status}</span>
        <span class="history-score">${item.risk}%</span>
      </div>
      <div class="history-url" title="${item.url}">${item.url}</div>
      <div class="history-time">${item.time}</div>
      <div class="rescan-hint">Click to re-scan</div>
    </div>
  `).join("");
  document.querySelectorAll(".history-item").forEach(el => {
    el.addEventListener("click", () => {
      const item = scanHistory[parseInt(el.dataset.idx)];
      if (item) { urlInput.value = item.url; runScan(); }
    });
  });
}


async function runScan() {
  const raw = urlInput.value.trim();
  if (!raw) { fieldNote.textContent = "Please enter a URL before scanning."; urlInput.focus(); return; }

  const ev = evaluateURL(raw);
  if (!ev.valid) {
    fieldNote.textContent = ev.message;
    statusPill.className = "status-pill neutral";
    statusPill.textContent = "Invalid Input";
    resultTitle.textContent = "Unable to scan";
    resultSub.textContent = ev.message;
    reasonList.innerHTML = "<li>Enter a properly formatted URL and try again.</li>";
    return;
  }

  
  [scanBtn, clearBtn, randomBtn].forEach(b => b.disabled = true);
  fieldNote.textContent = "Scan in progress…";
  resetStages();

  
  await stageActivate("stg1", 180); setProgress(12); await stageDone("stg1");

  
  await stageActivate("stg2", 280); setProgress(28); await stageDone("stg2");

  
  await stageActivate("stg3", 220); setProgress(45); await stageDone("stg3");

  
  await stageActivate("stg4", 200); setProgress(60); await stageDone("stg4");

  
  await stageActivate("stg5", 220); setProgress(75); await stageDone("stg5");

 
  await stageActivate("stg6", 0);
  setProgress(82);

  let gsbRes = null, vtRes = null;
  const gsbKey = gsbKeyInput.value.trim();
  const vtKey  = vtKeyInput.value.trim();

  if (gsbKey) {
    setPill(gsbStatusEl, "busy", "Checking…");
    gsbRes = await checkGSB(ev.normalized, gsbKey);
    if (gsbRes.ok) {
      setPill(gsbStatusEl, gsbRes.flagged ? "flagged" : "clean",
              gsbRes.flagged ? "⚠ Flagged!" : "✓ Clean");
    } else {
      setPill(gsbStatusEl, "error", "Error");
    }
  }

  if (vtKey) {
    setPill(vtStatusEl, "busy", "Checking…");
    vtRes = await checkVT(ev.normalized, vtKey);
    if (vtRes.ok) {
      setPill(vtStatusEl, vtRes.pending ? "clean" : vtRes.flagged ? "flagged" : "clean",
              vtRes.pending ? "Submitted" : vtRes.flagged ? `⚠ ${vtRes.malicious} flagged` : "✓ Clean");
    } else {
      setPill(vtStatusEl, "error", "CORS Error");
    }
  }

  await stageDone("stg6");
  setProgress(100);

  
  if (gsbRes?.ok && gsbRes.flagged) {
    ev.risk = Math.min(ev.risk + 35, 100);
    ev.reasons.push({ text: `Google Safe Browsing flagged this URL: ${gsbRes.threats.join(", ")}.`, type: "danger" });
    if (!ev.threats.includes("GSB FLAGGED")) ev.threats.push("GSB FLAGGED");
  }
  if (vtRes?.ok && !vtRes.pending && vtRes.flagged) {
    ev.risk = Math.min(ev.risk + 30, 100);
    ev.reasons.push({ text: `VirusTotal: ${vtRes.malicious} engines flagged this URL as malicious.`, type: "danger" });
    if (!ev.threats.includes("VT FLAGGED")) ev.threats.push("VT FLAGGED");
  }

  
  if (ev.risk >= RISK_PHISHING)    { ev.status = "Phishing";   ev.typeClass = "danger"; }
  else if (ev.risk >= RISK_SUSPICIOUS) { ev.status = "Suspicious"; ev.typeClass = "warn"; }

  renderResults(ev, gsbRes, vtRes);
  addToHistory(ev);

  latestReport = ev;
  exportTxtBtn.disabled = exportJsonBtn.disabled = false;

  [scanBtn, clearBtn, randomBtn].forEach(b => b.disabled = false);
  fieldNote.textContent = "Scan complete. Download or copy your report below.";
}


async function runBatchScan() {
  const lines = batchInput.value.split("\n").map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) return;
  batchResults.innerHTML = "";
  batchScanBtn.disabled = true;

  for (const line of lines.slice(0, 20)) {  // max 20
    const ev = evaluateURL(line);
    const url  = ev.valid ? ev.normalized : line;
    const risk = ev.valid ? ev.risk : "—";
    const cls  = !ev.valid ? "warn"
               : ev.typeClass === "danger" ? "danger"
               : ev.typeClass === "warn"   ? "warn"
               :                             "safe";
    const label = !ev.valid ? "Invalid" : ev.status;
    const item  = document.createElement("div");
    item.className = "batch-item";
    item.innerHTML = `
      <span class="b-url" title="${url}">${url}</span>
      <span class="b-pct">${ev.valid ? ev.risk+"%" : "—"}</span>
      <span class="b-badge ${cls}">${label}</span>
    `;
    item.style.opacity = "0";
    batchResults.appendChild(item);
    await sleep(40);
    item.style.transition = "opacity .3s";
    item.style.opacity = "1";
  }

  if (lines.length > 20) {
    const note = document.createElement("div");
    note.style.cssText = "font-size:11px;color:var(--muted);padding:6px 0;";
    note.textContent = `Showing 20 of ${lines.length} URLs.`;
    batchResults.appendChild(note);
  }

  batchScanBtn.disabled = false;
}

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function exportTxt() {
  if (!latestReport) return;
  const ev = latestReport;
  const lines = [
    "═══════════════════════════════════════",
    "  PhishGuard AI — Scan Report v2",
    "═══════════════════════════════════════",
    `URL          : ${ev.normalized}`,
    `Scanned At   : ${new Date().toLocaleString()}`,
    `Classification: ${ev.status}`,
    `Risk Score   : ${ev.risk}%`,
    `Confidence   : ${ev.confidence}%`,
    `Protocol     : ${ev.protocol}`,
    `Domain Style : ${ev.domainStyle}`,
    `Entropy      : ${ev.entropy.toFixed(2)} bits`,
    `Brand Alert  : ${ev.impersonated ? ev.impersonated : "None"}`,
    "",
    "Detected Threats:",
    ev.threats.length ? ev.threats.map(t => "  • " + t).join("\n") : "  None",
    "",
    "Reasoning (" + ev.reasons.length + " signals):",
    ...ev.reasons.map((r, i) => `  ${i+1}. [${r.type.toUpperCase()}] ${r.text}`),
    "",
    "Feature Metrics:",
    `  URL Length Risk   : ${ev.metrics.length}`,
    `  Special Char Risk : ${ev.metrics.special}`,
    `  Keyword Suspicion : ${ev.metrics.keyword}`,
    `  Subdomain Complex : ${ev.metrics.subdomain}`,
    `  Entropy Score     : ${ev.metrics.entropy}`,
    `  Encoding Risk     : ${ev.metrics.encoding}`,
    "═══════════════════════════════════════",
  ];
  downloadFile(lines.join("\n"), "phishguard-report.txt", "text/plain");
}

function exportJson() {
  if (!latestReport) return;
  const ev = latestReport;
  const payload = {
    tool: "PhishGuard AI v2",
    scannedAt: new Date().toISOString(),
    url: ev.normalized,
    classification: ev.status,
    riskScore: ev.risk,
    confidence: ev.confidence,
    protocol: ev.protocol,
    domainStyle: ev.domainStyle,
    entropy: parseFloat(ev.entropy.toFixed(2)),
    brandImpersonation: ev.impersonated || null,
    isWhitelisted: ev.isWhitelisted,
    detectedThreats: ev.threats,
    metrics: ev.metrics,
    reasons: ev.reasons,
  };
  downloadFile(JSON.stringify(payload, null, 2), "phishguard-report.json", "application/json");
}


function clearAll() {
  urlInput.value = "";
  resetUI();
}

async function pasteURL() {
  try {
    const text = await navigator.clipboard.readText();
    if (text) { urlInput.value = text.trim(); fieldNote.textContent = "URL pasted from clipboard."; }
  } catch { fieldNote.textContent = "Clipboard access blocked — paste manually."; }
}

function randomDemo() {
  urlInput.value = DEMO_URLS[Math.floor(Math.random() * DEMO_URLS.length)];
  fieldNote.textContent = "Demo URL loaded.";
  runScan();
}

async function copyReport() {
  if (!latestReport) return;
  const ev = latestReport;
  const text = [
    "PhishGuard AI Report",
    "URL: " + ev.normalized,
    "Classification: " + ev.status,
    "Risk Score: " + ev.risk + "%",
    "Confidence: " + ev.confidence + "%",
    "Threats: " + (ev.threats.join(", ") || "None"),
    "Reasons:",
    ...ev.reasons.map((r, i) => (i+1) + ". [" + r.type + "] " + r.text),
  ].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    copyReportBtn.textContent = "Copied ✓";
    setTimeout(() => copyReportBtn.textContent = "Copy Report", 1400);
  } catch {
    copyReportBtn.textContent = "Failed";
    setTimeout(() => copyReportBtn.textContent = "Copy Report", 1400);
  }
}

function initTheme() {
  if (localStorage.getItem("phishguard-theme") === "light")
    document.body.classList.add("light-theme");
}

function toggleTheme() {
  document.body.classList.toggle("light-theme");
  localStorage.setItem("phishguard-theme",
    document.body.classList.contains("light-theme") ? "light" : "dark");
}

function makeCollapsible(btnId, bodyId) {
  const btn  = $(btnId);
  const body = $(bodyId);
  if (!btn || !body) return;
  btn.addEventListener("click", () => {
    const open = body.classList.toggle("open");
    btn.classList.toggle("open", open);
  });
}


scanBtn.addEventListener("click", runScan);
clearBtn.addEventListener("click", clearAll);
randomBtn.addEventListener("click", randomDemo);
pasteBtn.addEventListener("click", pasteURL);
copyReportBtn.addEventListener("click", copyReport);
themeToggle.addEventListener("click", toggleTheme);
exportTxtBtn.addEventListener("click", exportTxt);
exportJsonBtn.addEventListener("click", exportJson);

$("batchScanBtn").addEventListener("click", runBatchScan);
$("batchClearBtn").addEventListener("click", () => {
  batchInput.value = "";
  batchResults.innerHTML = "";
});
$("clearHistBtn").addEventListener("click", () => {
  scanHistory = [];
  updateHistory();
});

urlInput.addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });

document.querySelectorAll(".sample-chip").forEach(chip => {
  chip.addEventListener("click", () => {
    urlInput.value = chip.dataset.url;
    fieldNote.textContent = "Sample URL loaded. Press Run Scan.";
  });
});

makeCollapsible("apiToggle", "apiBody");
makeCollapsible("batchToggle", "batchBody");


initTheme();
resetUI();
updateHistory();