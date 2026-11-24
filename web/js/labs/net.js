// IPv4 helpers for the lab simulator. Pure functions, no DOM.

export function ipToInt(ip) {
  const p = String(ip).trim().split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x)) return null;
    const v = Number(x);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}
export function intToIp(n) {
  n = n >>> 0;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
export const isIp = (s) => ipToInt(s) !== null;
export function lenToMask(len) { return len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0; }
export function maskToLen(mask) {
  const m = typeof mask === "number" ? mask : ipToInt(mask);
  if (m === null) return null;
  let len = 0, seenZero = false;
  for (let i = 31; i >= 0; i--) {
    const bit = (m >>> i) & 1;
    if (bit && seenZero) return null;
    if (bit) len++; else seenZero = true;
  }
  return len;
}
// Parse "10.1.1.0/24", "10.1.1.0 255.255.255.0" or a bare ip (→ /32). Returns {ip, len} or null.
export function parsePrefix(s, bareLen = 32) {
  if (s == null) return null;
  const t = String(s).trim().replace(/\s+/g, " ");
  let m = t.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
  if (m) { const ip = ipToInt(m[1]); const len = Number(m[2]); return ip === null || len > 32 ? null : { ip, len }; }
  m = t.match(/^(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$/);
  if (m) { const ip = ipToInt(m[1]); const len = maskToLen(m[2]); return ip === null || len === null ? null : { ip, len }; }
  const ip = ipToInt(t);
  return ip === null ? null : { ip, len: bareLen };
}
export const network = (p) => (p.ip & lenToMask(p.len)) >>> 0;
export function inPrefix(ip, p) {
  const n = typeof ip === "number" ? ip : ipToInt(ip);
  if (n === null || !p) return false;
  const m = lenToMask(p.len);
  return ((n & m) >>> 0) === ((p.ip & m) >>> 0);
}
export const maskStr = (len) => intToIp(lenToMask(len));
export const prefixStr = (p) => `${intToIp(network(p))}/${p.len}`;
export const ipMaskStr = (p) => `${intToIp(p.ip)} ${maskStr(p.len)}`;
export function isPrivate(ip) {
  const n = typeof ip === "number" ? ip : ipToInt(ip);
  return inPrefix(n, { ip: ipToInt("10.0.0.0"), len: 8 }) || inPrefix(n, { ip: ipToInt("172.16.0.0"), len: 12 }) ||
    inPrefix(n, { ip: ipToInt("192.168.0.0"), len: 16 }) || inPrefix(n, { ip: ipToInt("100.64.0.0"), len: 10 });
}
export function inRange(ip, lo, hi) {
  const n = typeof ip === "number" ? ip : ipToInt(ip);
  return n !== null && n >= ipToInt(lo) && n <= ipToInt(hi);
}
// A tiny deterministic PRNG so outputs (ports, session ids, timings) are stable per lab run.
export function rng(seed) {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}
export const hex = (n, w = 8) => (n >>> 0).toString(16).padStart(w, "0");
