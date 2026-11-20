// Карта блокировок: принимает анонимные результаты проверки blockcheck и отдаёт сводку
// Храним только время, страну, регион и оператора (их определяет Cloudflare) и результаты. IP не сохраняется
const SERVICES = ["YouTube", "Twitch", "Netflix", "Spotify", "SoundCloud", "Instagram", "Facebook", "X (Twitter)",
  "Reddit", "LinkedIn", "WhatsApp", "Telegram Web", "Discord", "Signal", "ChatGPT", "Gemini", "Google", "Википедия"];
const LOCAL = ["Яндекс", "ВКонтакте", "Госуслуги"];
const STATES = new Set(["ok", "slow", "bad"]);
const MIN_GROUP = 3;          // группы меньше этого не показываем: шум и приватность
const KEEP_DAYS = 30;

const OPERATORS = [
  [/mts pjsc|^mts |mobile telesystems/i, "МТС"], [/vimpelcom|beeline/i, "Билайн"], [/megafon/i, "МегаФон"],
  [/tele2|t2 mobile/i, "Т2"], [/rostelecom/i, "Ростелеком"], [/er-telecom|dom\.ru/i, "Дом.ру"],
  [/yota|scartel/i, "Yota"], [/mgts|moscow city telephone/i, "МГТС"], [/akado/i, "Акадо"],
];
const opName = org => { if (!org) return "Другой"; for (const [rx, n] of OPERATORS) if (rx.test(org)) return n; return org.slice(0, 40); };

const cors = origin => ({
  "Access-Control-Allow-Origin": origin && /^https:\/\/kochurin\.github\.io$|^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(origin) ? origin : "https://kochurin.github.io",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Vary": "Origin",
});
const json = (data, origin, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin), ...extra } });

async function sha(text) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

async function report(req, env, origin) {
  let body;
  try { body = await req.json(); } catch { return json({ error: "bad json" }, origin, 400); }
  const res = {};
  for (const name of SERVICES.concat(LOCAL)) {
    const v = body?.r?.[name];
    if (!STATES.has(v)) return json({ error: "bad result" }, origin, 400);
    res[name] = v;
  }
  const cf = req.cf || {};
  // не чаще раза в 10 минут с одного адреса и оператора: храним только солёный хеш, который нельзя развернуть в IP
  const ip = req.headers.get("CF-Connecting-IP") || "";
  const slot = Math.floor(Date.now() / 600000);
  const h = await sha(`${env.SALT || "salt"}|${slot}|${ip}`);
  const dup = await env.DB.prepare("INSERT OR IGNORE INTO seen (h, ts) VALUES (?, ?)").bind(h, Date.now()).run();
  if (!dup.meta.changes) return json({ ok: true, counted: false }, origin);

  // Крым, Севастополь, ДНР, ЛНР, Запорожская и Херсонская области приходят от геобаз с кодами Украины
  // Переводим их в свои коды; сети украинских операторов не трогаем
  let country = cf.country || null, rc = cf.regionCode || null;
  const NEW = { "43": "CR", "40": "SEV", "14": "DPR", "09": "LPR", "23": "ZAP", "65": "KHE" };
  if (country === "UA" && NEW[rc] && !/kyivstar|vodafone ukr|lifecell|ukrtelecom|volia|datagroup|triolan/i.test(cf.asOrganization || "")) {
    country = "RU"; rc = NEW[rc];
  }
  const foreignBad = SERVICES.filter(s => res[s] === "bad").length;
  const localOk = LOCAL.some(s => res[s] !== "bad");
  const wl = localOk && foreignBad >= SERVICES.length * 0.7 ? 1 : 0;
  await env.DB.prepare("INSERT INTO reports (ts, country, region, rc, op, res, wl) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(Date.now(), country, cf.region || null, rc, opName(cf.asOrganization), JSON.stringify(res), wl).run();
  return json({ ok: true, counted: true, op: opName(cf.asOrganization), region: cf.region || null }, origin);
}

function group(rows, key, keepSmall = false) {
  const m = new Map();
  for (const r of rows) {
    const k = r[key] || "Не определено";
    let g = m.get(k);
    if (!g) m.set(k, g = { name: k, n: 0, wl: 0, bad: Object.fromEntries(SERVICES.map(s => [s, 0])) });
    g.n++; g.wl += r.wl;
    for (const s of SERVICES) if (r.res[s] !== "ok") g.bad[s]++;
  }
  // в маленьких группах отдаём только число проверок, без разбивки: шум и приватность
  return [...m.values()].filter(g => keepSmall || g.n >= MIN_GROUP).map(g => g.n < MIN_GROUP ? { name: g.name, n: g.n } : ({
    name: g.name, n: g.n, wl: Math.round(100 * g.wl / g.n),
    bad: Object.fromEntries(SERVICES.map(s => [s, Math.round(100 * g.bad[s] / g.n)])),
  })).sort((a, b) => b.n - a.n);
}

async function stats(url, env, origin) {
  const hours = Math.min(Math.max(parseInt(url.searchParams.get("hours") || "24", 10) || 24, 1), 24 * 7);
  const since = Date.now() - hours * 3600e3;
  const { results } = await env.DB.prepare("SELECT region, rc, op, res, wl FROM reports WHERE ts > ? AND country = 'RU'").bind(since).all();
  const rows = results.map(r => ({ ...r, res: JSON.parse(r.res) }));
  const all = group(rows.map(r => ({ ...r, all: "Россия" })), "all")[0] || null;
  let ooni = null;
  try { ooni = await ooniStats(env); } catch {}
  return json({ hours, total: rows.length, services: SERVICES, all, operators: group(rows, "op"), regions: group(rows, "rc", true), ooni, updated: new Date().toISOString() },
    origin, 200, { "Cache-Control": "public, max-age=120" });
}

// ---------- OONI: открытые измерения добровольцев (ooni.org), подтягиваем раз в час ----------
const OONI_DOMAINS = {
  "YouTube": ["www.youtube.com"], "Instagram": ["www.instagram.com"], "WhatsApp": ["www.whatsapp.com"],
  "Telegram Web": ["telegram.org"], "Discord": ["discord.com"], "ChatGPT": ["chatgpt.com", "chat.openai.com"],
  "X (Twitter)": ["twitter.com", "x.com"], "Facebook": ["www.facebook.com"], "Google": ["www.google.com"],
};
const OONI_DAYS = 7;          // OONI публикует с задержкой, берём неделю
const OONI_MIN = 30;          // оператора показываем, если у него хотя бы 30 измерений

async function ooniImport(env) {
  const until = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
  const since = new Date(Date.now() - OONI_DAYS * 864e5).toISOString().slice(0, 10);
  const rows = [];
  for (const [svc, domains] of Object.entries(OONI_DOMAINS)) {
    for (const d of domains) {
      const u = `https://api.ooni.io/api/v1/aggregation?probe_cc=RU&test_name=web_connectivity&domain=${d}&since=${since}&until=${until}&axis_x=probe_asn`;
      const r = await fetch(u, { headers: { "User-Agent": "blockmap (github.com/Kochurin/blockcheck)" } });
      if (!r.ok) continue;
      for (const x of (await r.json()).result || []) rows.push([svc, x.probe_asn, x.measurement_count, x.anomaly_count + x.confirmed_count]);
    }
  }
  if (!rows.length) return;
  const stmts = [env.DB.prepare("DELETE FROM ooni")];
  for (const r of rows) stmts.push(env.DB.prepare("INSERT INTO ooni (svc, asn, n, bad) VALUES (?, ?, ?, ?)").bind(...r));
  stmts.push(env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('ooni_updated', ?)").bind(new Date().toISOString()));
  await env.DB.batch(stmts);
  // названия сетей (кому принадлежит AS) берём из RIPE, кешируем навсегда
  const { results } = await env.DB.prepare(
    "SELECT o.asn, SUM(o.n) AS t FROM ooni o LEFT JOIN asn a ON a.asn = o.asn WHERE a.asn IS NULL GROUP BY o.asn ORDER BY t DESC LIMIT 25").all();
  for (const { asn } of results) {
    try {
      const j = await (await fetch(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}`)).json();
      await env.DB.prepare("INSERT OR REPLACE INTO asn (asn, holder) VALUES (?, ?)").bind(asn, j?.data?.holder || "").run();
    } catch {}
  }
}

async function ooniStats(env) {
  const { results } = await env.DB.prepare("SELECT o.svc, o.asn, o.n, o.bad, a.holder FROM ooni o LEFT JOIN asn a ON a.asn = o.asn").all();
  if (!results.length) return null;
  const upd = await env.DB.prepare("SELECT v FROM meta WHERE k = 'ooni_updated'").first();
  const svcs = Object.keys(OONI_DOMAINS);
  const ops = new Map(), all = Object.fromEntries(svcs.map(s => [s, [0, 0]]));
  for (const r of results) {
    const name = r.holder ? opName(r.holder) : `AS${r.asn}`;
    let g = ops.get(name);
    if (!g) ops.set(name, g = { name, n: 0, s: Object.fromEntries(svcs.map(s => [s, [0, 0]])) });
    g.n += r.n; g.s[r.svc][0] += r.n; g.s[r.svc][1] += r.bad;
    all[r.svc][0] += r.n; all[r.svc][1] += r.bad;
  }
  const pct = ([n, b]) => n ? Math.round(100 * b / n) : null;
  return {
    days: OONI_DAYS, updated: upd?.v || null, services: svcs,
    all: Object.fromEntries(svcs.map(s => [s, pct(all[s])])),
    total: Object.values(all).reduce((t, [n]) => t + n, 0),
    operators: [...ops.values()].filter(g => g.n >= OONI_MIN).sort((a, b) => b.n - a.n).slice(0, 15)
      .map(g => ({ name: g.name, n: g.n, bad: Object.fromEntries(svcs.map(s => [s, pct(g.s[s])])) })),
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), origin = req.headers.get("Origin");
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(origin) });
    if (url.pathname === "/report" && req.method === "POST") return report(req, env, origin);
    if (url.pathname === "/stats" && req.method === "GET") return stats(url, env, origin);
    return json({ name: "blockmap", endpoints: ["POST /report", "GET /stats?hours=24"] }, origin);
  },
  async scheduled(event, env) {
    if (event.cron !== "17 3 * * *") { await ooniImport(env); return; }
    await env.DB.prepare("DELETE FROM reports WHERE ts < ?").bind(Date.now() - KEEP_DAYS * 864e5).run();
    await env.DB.prepare("DELETE FROM seen WHERE ts < ?").bind(Date.now() - 864e5).run();
  },
};
