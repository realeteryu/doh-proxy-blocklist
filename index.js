const UPSTREAM = 'https://security.cloudflare-dns.com/dns-query';
const BLOCKLIST_URL = 'https://cdn.jsdelivr.net/gh/realeteryu/dns-blocklists@main/output/blocklist.txt';
// const BLOCKLIST_TTL = 24 * 60 * 60 * 1000;
const BLOCKLIST_TTL = 5 * 60 * 1000; // 5 minut
const WIRE = 'application/dns-message';
const JSON_CT = 'application/dns-json';

let blocklist = null;
let blocklistAt = 0;

export default {
  async fetch(req, _env, ctx) { return handle(req, ctx); },
};

async function handle(req, ctx) {
  const url = new URL(req.url);

  if (url.pathname === '/' && url.search === '') {
    return new Response(`status: ok\nblocklist: ${blocklist ? blocklist.size : 0}\n`);
  }
  if (url.pathname !== '/dns-query') {
    return new Response('Not Found', { status: 404 });
  }

  let set = null;
  try { set = await getBlocklist(ctx); } catch {}

  // JSON API (GET ?name=example.com&type=A)
  if (req.method === 'GET' && url.searchParams.has('name')) {
    const name = url.searchParams.get('name');
    const type = url.searchParams.get('type') || 'A';
    if (set && isBlocked(set, name)) {
      return jsonResponse({
        Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false,
        Question: [{ name, type }], Answer: [],
      });
    }
    const up = await fetch(UPSTREAM + url.search, { headers: { accept: JSON_CT } });
    return new Response(up.body, {
      status: up.status,
      headers: { 'content-type': JSON_CT, 'access-control-allow-origin': '*' },
    });
  }

  // Wire GET (?dns=<base64url>)
  if (req.method === 'GET' && url.searchParams.has('dns')) {
    const dnsParam = url.searchParams.get('dns');
    const bytes = b64urlDecode(dnsParam);
    if (bytes && set) {
      const q = extractQname(bytes);
      if (q && isBlocked(set, q)) {
        const resp = buildNxdomain(bytes);
        if (resp) return wireResponse(resp);
      }
    }
    const up = await fetch(UPSTREAM + '?dns=' + dnsParam, { headers: { accept: WIRE } });
    return new Response(up.body, {
      status: up.status,
      headers: { 'content-type': WIRE, 'access-control-allow-origin': '*' },
    });
  }

  // Wire POST (Intra domyślnie używa tego wariantu)
  if (req.method === 'POST') {
    const ct = (req.headers.get('content-type') || '').toLowerCase();
    if (!ct.startsWith(WIRE)) {
      return new Response('Unsupported content-type', { status: 415 });
    }
    const bytes = new Uint8Array(await req.arrayBuffer());
    if (set) {
      const q = extractQname(bytes);
      if (q && isBlocked(set, q)) {
        const resp = buildNxdomain(bytes);
        if (resp) return wireResponse(resp);
      }
    }
    const up = await fetch(UPSTREAM, {
      method: 'POST',
      headers: { accept: WIRE, 'content-type': WIRE },
      body: bytes,
    });
    return new Response(up.body, {
      status: up.status,
      headers: { 'content-type': WIRE, 'access-control-allow-origin': '*' },
    });
  }

  return new Response('Bad Request', { status: 400 });
}

function wireResponse(b) {
  return new Response(b, {
    headers: { 'content-type': WIRE, 'access-control-allow-origin': '*' },
  });
}

function jsonResponse(o) {
  return new Response(JSON.stringify(o), {
    headers: { 'content-type': JSON_CT, 'access-control-allow-origin': '*' },
  });
}

// -------- blocklist loading (stale-while-revalidate) --------

async function getBlocklist(ctx) {
  const now = Date.now();
  if (blocklist && now - blocklistAt < BLOCKLIST_TTL) return blocklist;
  if (blocklist) { ctx.waitUntil(refresh()); return blocklist; }
  return refresh();
}

async function refresh() {
  try {
    const res = await fetch(BLOCKLIST_URL, { cf: { cacheTtl: 3600 } });
    if (!res.ok) return blocklist;
    const text = await res.text();
    const s = new Set();
    for (const line of text.split('\n')) {
      const d = line.trim().toLowerCase();
      if (d && d.charCodeAt(0) !== 35) s.add(d); // pomiń '#'
    }
    if (s.size) { blocklist = s; blocklistAt = Date.now(); }
  } catch {}
  return blocklist;
}

function isBlocked(set, name) {
  if (!name) return false;
  name = name.toLowerCase();
  if (name.endsWith('.')) name = name.slice(0, -1);
  if (set.has(name)) return true;
  let i = name.indexOf('.');
  while (i !== -1) {
    if (set.has(name.slice(i + 1))) return true;
    i = name.indexOf('.', i + 1);
  }
  return false;
}

// -------- minimal DNS wire format handling --------

function extractQname(b) {
  if (b.length < 13) return null;
  let i = 12;
  const labels = [];
  while (i < b.length) {
    const len = b[i];
    if (len === 0) return labels.length ? labels.join('.').toLowerCase() : null;
    if (len > 63 || i + 1 + len > b.length) return null;
    let label = '';
    for (let j = 0; j < len; j++) {
      const c = b[i + 1 + j];
      if (c < 32 || c > 126) return null;
      label += String.fromCharCode(c);
    }
    labels.push(label);
    i += 1 + len;
  }
  return null;
}

function buildNxdomain(qb) {
  if (qb.length < 13) return null;
  let i = 12;
  while (i < qb.length) {
    const len = qb[i];
    if (len === 0) break;
    if (len > 63) return null;
    i += 1 + len;
  }
  if (i >= qb.length) return null;
  i += 5; // null + QTYPE + QCLASS
  if (i > qb.length) return null;
  const r = new Uint8Array(i);
  r[0] = qb[0]; r[1] = qb[1];
  r[2] = 0x81; // QR=1, RD=1
  r[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
  r[4] = qb[4]; r[5] = qb[5]; // echo QDCOUNT
  r.set(qb.subarray(12, i), 12);
  return r;
}

function b64urlDecode(s) {
  try {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    const bin = atob(b);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return null; }
}
