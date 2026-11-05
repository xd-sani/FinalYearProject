/*
 * COLOUR Visual Cryptography + MD5 / SHA-256 / HMAC integrity check  -  complete program, plain JavaScript
 *
 * No npm install needed. Only Node.js built-ins are used (fs, zlib, crypto).
 *   - MD5, SHA-256 and HMAC-SHA-256 are written from scratch below.
 *   - Node's "crypto" is used only for random numbers and for checking our own hashes.
 *
 * Run:   node vc_full.js                          built-in colour picture, mode "visual"
 *        node vc_full.js photo.png                your own colour picture (PNG, or JPG after: npm install jpeg-js)
 *        node vc_full.js photo.png --mode=xor     exact colours (lossless), shares are not "stackable by eye"
 *        node vc_full.js photo.png --max=400      longest side is shrunk to 400 px (default 300, 0 = keep size)
 *        node vc_full.js photo.png --gamma=0.5    brighten dark pictures before splitting (visual mode only, default 1 = off)
 *
 * Modes
 *   visual : real visual cryptography. Each of R, G, B is turned into dots (halftone) and split into
 *            two shares with 2x2 sub-pixels. Stacking the shares (like two transparencies) shows the picture
 *            in dithered colour, darker than the original (this is normal for visual cryptography).
 *   xor    : colour secret sharing. Share 1 is random noise, Share 2 = picture XOR Share 1. Combining the two
 *            gives the EXACT original colours. Same size as the picture, but it needs a computer, not eyes.
 */
"use strict";
const fs = require("fs");
const zlib = require("zlib");
const crypto = require("crypto");

// ============================================================================
// PART 1.  HASH FUNCTIONS FROM SCRATCH
// ============================================================================
const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
const toHex = (bytes) => Buffer.from(bytes).toString("hex");
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));

// Padding: append a 1 bit, then zeros, then the message length in bits (64-bit),
// so that the total length is a multiple of 64 bytes (512 bits).
function pad(data, littleEndian) {
  const n = data.length;
  const total = n + 1 + (((55 - n) % 64) + 64) % 64 + 8;
  const out = new Uint8Array(total);
  out.set(data);
  out[n] = 0x80;
  new DataView(out.buffer).setBigUint64(total - 8, BigInt(n) * 8n, littleEndian);
  return out;
}

// ---------------------------- MD5 (128-bit digest) -------------------------
const MD5_SHIFT = [
  ...Array(4).fill([7, 12, 17, 22]).flat(), ...Array(4).fill([5, 9, 14, 20]).flat(),
  ...Array(4).fill([4, 11, 16, 23]).flat(), ...Array(4).fill([6, 10, 15, 21]).flat(),
];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

function md5(data) {
  const msg = pad(data, true);                                   // little-endian length
  const view = new DataView(msg.buffer);
  const M = new Uint32Array(16);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;   // start values
  for (let off = 0; off < msg.length; off += 64) {               // every 512-bit block
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {                               // 4 rounds x 16 steps
      let F, g;
      if (i < 16)      { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
      else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, MD5_SHIFT[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new DataView(new ArrayBuffer(16));
  [a0, b0, c0, d0].forEach((v, i) => out.setUint32(i * 4, v, true));
  return new Uint8Array(out.buffer);
}

// ------------------------- SHA-256 (256-bit digest) ------------------------
const primes = (n) => { const p = []; for (let x = 2; p.length < n; x++) if (p.every((q) => x % q)) p.push(x); return p; };
const icbrt = (n) => { let lo = 0n, hi = 1n << BigInt(Math.ceil(n.toString(2).length / 3) + 2);
  while (lo < hi) { const m = (lo + hi + 1n) / 2n; if (m ** 3n <= n) lo = m; else hi = m - 1n; } return lo; };
const isqrt = (n) => { let x = BigInt(Math.floor(Math.sqrt(Number(n)))); while (x * x > n) x--; while ((x + 1n) ** 2n <= n) x++; return x; };
const PR = primes(64);
const SHA_H0 = PR.slice(0, 8).map((p) => Number(isqrt(BigInt(p) << 64n) & 0xffffffffn)); // sqrt of first 8 primes
const SHA_K = PR.map((p) => Number(icbrt(BigInt(p) << 96n) & 0xffffffffn));              // cbrt of first 64 primes

function sha256(data) {
  const msg = pad(data, false);                                  // big-endian length
  const view = new DataView(msg.buffer);
  const H = Uint32Array.from(SHA_H0), w = new Uint32Array(64);
  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);   // message schedule: 16 words -> 64 words
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {                               // 64 rounds
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;   // Uint32Array wraps at 2^32
  }
  const out = new DataView(new ArrayBuffer(32));
  H.forEach((v, i) => out.setUint32(i * 4, v, false));
  return new Uint8Array(out.buffer);
}

// ------------- HMAC-SHA-256: a hash that also needs a secret key -----------
function hmacSha256(key, msg) {
  let k = Uint8Array.from(key);
  if (k.length > 64) k = sha256(k);
  const block = new Uint8Array(64); block.set(k);
  const inner = sha256(concat(block.map((b) => b ^ 0x36), msg));
  return sha256(concat(block.map((b) => b ^ 0x5c), inner));
}
const md5Hex = (d) => toHex(md5(d));
const sha256Hex = (d) => toHex(sha256(d));
const sameHex = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// ============================================================================
// PART 2.  COLOUR PNG READ / WRITE  (so we can save shares and hash the exact file bytes)
// ============================================================================
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
// rgb: Uint8Array of R,G,B,R,G,B... -> PNG file bytes (24-bit colour)
function encodePng(rgb, W, H) {
  const raw = Buffer.alloc((W * 3 + 1) * H);
  for (let y = 0; y < H; y++) Buffer.from(rgb.buffer, rgb.byteOffset + y * W * 3, W * 3).copy(raw, y * (W * 3 + 1) + 1);
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}
// PNG file -> RGB bytes. Supports gray, gray+alpha, RGB, RGBA (8 or 16 bit) and 8-bit palette PNGs.
// Transparent areas are placed on a white background.
function decodePng(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error("This is not a PNG file");
  let pos = 8, W, H, depth, ctype, interlace, plte = null, trns = null; const idat = [];
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos), type = buf.toString("ascii", pos + 4, pos + 8), data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === "IHDR") { W = data.readUInt32BE(0); H = data.readUInt32BE(4); depth = data[8]; ctype = data[9]; interlace = data[12]; }
    if (type === "PLTE") plte = data;
    if (type === "tRNS") trns = data;
    if (type === "IDAT") idat.push(data);
    pos += 12 + len;
  }
  if (interlace) throw new Error("Interlaced PNG is not supported. Re-save the image as a normal (non-interlaced) PNG.");
  if (![1, 2, 4, 8, 16].includes(depth) || (depth < 8 && ctype !== 0 && ctype !== 3)) throw new Error(`${depth}-bit PNG of this type is not supported. Re-save the image as an 8-bit PNG.`);
  const ch = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[ctype], bps = Math.max(depth, 8) / 8, bpp = ch * bps, stride = Math.ceil(W * ch * depth / 8);
  const raw = zlib.inflateSync(Buffer.concat(idat)), px = Buffer.alloc(stride * H);
  for (let y = 0; y < H; y++) {                                  // undo the PNG row filters
    const ft = raw[y * (stride + 1)];
    for (let i = 0; i < stride; i++) {
      const cur = raw[y * (stride + 1) + 1 + i];
      const a = i >= bpp ? px[y * stride + i - bpp] : 0, b = y ? px[(y - 1) * stride + i] : 0, c = y && i >= bpp ? px[(y - 1) * stride + i - bpp] : 0;
      let v = cur;
      if (ft === 1) v += a; else if (ft === 2) v += b; else if (ft === 3) v += (a + b) >> 1;
      else if (ft === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      px[y * stride + i] = v & 255;
    }
  }
  const rgb = new Uint8Array(W * H * 3);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const i = y * W + x, base = y * stride;
    let r, g, b, a = 255;
    if (depth < 8) {                                             // 1, 2 or 4 bits per pixel (gray or palette)
      const bit = x * depth, v = (px[base + (bit >> 3)] >> (8 - depth - (bit & 7))) & ((1 << depth) - 1);
      if (ctype === 0) r = g = b = Math.round(v * 255 / ((1 << depth) - 1));
      else { r = plte[v * 3]; g = plte[v * 3 + 1]; b = plte[v * 3 + 2]; if (trns && v < trns.length) a = trns[v]; }
    } else {
      const s = (k) => px[base + x * bpp + k * bps];             // sample k (high byte if 16-bit)
      if (ctype === 0) r = g = b = s(0);
      else if (ctype === 2) { r = s(0); g = s(1); b = s(2); }
      else if (ctype === 3) { const p = s(0); r = plte[p * 3]; g = plte[p * 3 + 1]; b = plte[p * 3 + 2]; if (trns && p < trns.length) a = trns[p]; }
      else if (ctype === 4) { r = g = b = s(0); a = s(1); }
      else { r = s(0); g = s(1); b = s(2); a = s(3); }
    }
    rgb[i * 3] = (r * a + 255 * (255 - a)) / 255; rgb[i * 3 + 1] = (g * a + 255 * (255 - a)) / 255; rgb[i * 3 + 2] = (b * a + 255 * (255 - a)) / 255;
  }
  return { rgb, W, H };
}
// Reads PNG directly. For JPG files it uses the small "jpeg-js" package (npm install jpeg-js), or asks you to convert the file.
function decodeImage(buf, name) {
  if (buf.length > 8 && buf.readUInt32BE(0) === 0x89504e47) return decodePng(buf);
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {          // JPEG signature
    let jpeg;
    try { jpeg = require("jpeg-js"); }
    catch (e) {
      throw new Error(`${name} is a JPG file (renamed to .png?). Fix it in one of two ways:\n` +
        "  1) run:  npm install jpeg-js        (then run this program again), or\n" +
        "  2) open the picture in Paint, choose File > Save as > PNG picture, and use that file.");
    }
    const { data, width: W, height: H } = jpeg.decode(buf, { useTArray: true, formatAsRGBA: true });
    const rgb = new Uint8Array(W * H * 3);
    for (let i = 0; i < W * H; i++) for (let c = 0; c < 3; c++) rgb[i * 3 + c] = data[i * 4 + c];
    return { rgb, W, H };
  }
  throw new Error(`${name} is not a PNG or JPG picture. Convert it to PNG first (Paint: File > Save as > PNG picture).`);
}
// Shrink big pictures with a box average, so shares stay a sensible size
function resize(rgb, W, H, maxSide) {
  if (!maxSide || Math.max(W, H) <= maxSide) return { rgb, W, H };
  const sc = maxSide / Math.max(W, H), nw = Math.max(1, Math.round(W * sc)), nh = Math.max(1, Math.round(H * sc));
  const out = new Uint8Array(nw * nh * 3);
  for (let y = 0; y < nh; y++) for (let x = 0; x < nw; x++) {
    const x0 = Math.floor(x / sc), x1 = Math.min(W, Math.max(x0 + 1, Math.ceil((x + 1) / sc)));
    const y0 = Math.floor(y / sc), y1 = Math.min(H, Math.max(y0 + 1, Math.ceil((y + 1) / sc)));
    const sum = [0, 0, 0]; let n = 0;
    for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) { for (let c = 0; c < 3; c++) sum[c] += rgb[(yy * W + xx) * 3 + c]; n++; }
    for (let c = 0; c < 3; c++) out[(y * nw + x) * 3 + c] = Math.round(sum[c] / n);
  }
  return { rgb: out, W: nw, H: nh };
}

// ============================================================================
// PART 3.  COLOUR VISUAL CRYPTOGRAPHY
// ============================================================================
// ---- 3a. mode "visual": halftone each colour channel, then split with 2x2 patterns ----
// 1 = dark sub-pixel (that colour is blocked), 0 = light. Each pattern has 2 dark + 2 light sub-pixels.
const PATTERNS = [[1, 1, 0, 0], [0, 0, 1, 1], [1, 0, 1, 0], [0, 1, 0, 1], [1, 0, 0, 1], [0, 1, 1, 0]];

// Floyd-Steinberg error diffusion: a 0..255 channel becomes dots (1 = dark dot)
function halftone(rgb, c, w, h, gamma = 1) {   // gamma < 1 makes the picture brighter before it is turned into dots
  const v = new Float32Array(w * h), dark = new Uint8Array(w * h);
  for (let i = 0; i < w * h; i++) v[i] = 255 * Math.pow(rgb[i * 3 + c] / 255, gamma);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = y * w + x, old = v[i], nw = old < 128 ? 0 : 255, err = old - nw;
    dark[i] = nw === 0 ? 1 : 0;
    if (x + 1 < w) v[i + 1] += err * 7 / 16;
    if (y + 1 < h) { if (x > 0) v[i + w - 1] += err * 3 / 16; v[i + w] += err * 5 / 16; if (x + 1 < w) v[i + w + 1] += err / 16; }
  }
  return dark;
}
function visualShares(rgb, w, h, gamma = 1) {
  const SW = w * 2, SH = h * 2, s1 = new Uint8Array(SW * SH * 3), s2 = new Uint8Array(SW * SH * 3);
  for (let c = 0; c < 3; c++) {                                   // R, G and B each get their own pair of shares
    const dark = halftone(rgb, c, w, h, gamma);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
      const p = PATTERNS[crypto.randomInt(6)];                    // random pattern for Share 1
      for (let k = 0; k < 4; k++) {
        const idx = (2 * y + (k >> 1)) * SW + 2 * x + (k & 1);
        const q = dark[y * w + x] ? 1 - p[k] : p[k];              // dark dot: opposite pattern, light dot: same pattern
        s1[idx * 3 + c] = p[k] ? 0 : 255;
        s2[idx * 3 + c] = q ? 0 : 255;
      }
    }
  }
  return { s1, s2, SW, SH };
}
// stacking two transparencies: a colour passes only if BOTH shares let it pass
const visualStack = (a, b) => a.map((v, i) => (v === 0 || b[i] === 0 ? 0 : 255));
// Cheating attack: the attacker holds Share 1 and builds a Share 2 that shows a picture of his choice
function visualForge(s1, fakeRgb, w, h) {
  const SW = w * 2, out = new Uint8Array(s1.length);
  for (let c = 0; c < 3; c++) {
    const dark = halftone(fakeRgb, c, w, h);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) for (let k = 0; k < 4; k++) {
      const idx = (2 * y + (k >> 1)) * SW + 2 * x + (k & 1), p = s1[idx * 3 + c] === 0 ? 1 : 0;
      out[idx * 3 + c] = (dark[y * w + x] ? 1 - p : p) ? 0 : 255;
    }
  }
  return out;
}

// ---- 3b. mode "xor": exact colours. Share 1 = random, Share 2 = picture XOR Share 1 ----
function xorShares(rgb, w, h) {
  const s1 = crypto.randomBytes(rgb.length), s2 = new Uint8Array(rgb.length);
  for (let i = 0; i < rgb.length; i++) s2[i] = rgb[i] ^ s1[i];
  return { s1: new Uint8Array(s1), s2, SW: w, SH: h };
}
const xorStack = (a, b) => a.map((v, i) => v ^ b[i]);
const xorForge = (s1, fakeRgb) => Uint8Array.from(fakeRgb, (v, i) => v ^ s1[i]);

const MODES = {
  visual: { shares: visualShares, stack: visualStack, forge: (s1, fake, w, h) => visualForge(s1, fake, w, h),
            tamper: (s) => { const t = s.slice(), i = Math.floor(t.length / 2); t[i] = t[i] === 0 ? 255 : 0; return t; } },
  xor:    { shares: xorShares, stack: xorStack, forge: (s1, fake) => xorForge(s1, fake),
            tamper: (s) => { const t = s.slice(); t[Math.floor(t.length / 2)] ^= 1; return t; } },
};

// ---- Built-in pictures, so the program runs without any input file ----
function demoPicture(w, h) {            // sky gradient, sun, hills and a red house
  const rgb = new Uint8Array(w * h * 3), lerp = (a, b, t) => Math.round(a + (b - a) * t);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const t = y / h; let c = [lerp(40, 255, t), lerp(100, 175, t), lerp(215, 90, t)];                  // sky
    if (Math.hypot(x - w * 0.72, y - h * 0.3) < h * 0.14) c = [255, 225, 60];                            // sun
    if (y > h * 0.68 + 8 * Math.sin(x / 16)) c = [30, 130, 55];                                          // hills
    if (y > h * 0.8) c = [20, 95, 150];                                                                  // lake
    if (x > w * 0.18 && x < w * 0.38 && y > h * 0.5 && y < h * 0.72) c = [200, 40, 40];                  // house
    if (y > h * 0.36 && y <= h * 0.5 && Math.abs(x - w * 0.28) < (y - h * 0.36) * 1.3) c = [120, 70, 30]; // roof
    rgb.set(c, (y * w + x) * 3);
  }
  return rgb;
}
// fake picture used by the attacker: a red cross on white
function fakePicture(w, h) {
  const rgb = new Uint8Array(w * h * 3).fill(255);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const xs = x * h / w;                                          // keeps the cross diagonal on wide images
    if (Math.abs(xs - y) < 8 || Math.abs(xs - (h - 1 - y)) < 8) rgb.set([225, 20, 20], (y * w + x) * 3);
  }
  return rgb;
}

// ============================================================================
// PART 4.  SENDER AND RECEIVER
// ============================================================================
function digestsOf(fileBytes) { return { md5: md5Hex(fileBytes), sha256: sha256Hex(fileBytes) }; }

// Receiver: (1) check the HMAC on the digest list, (2) compare every share's SHA-256 (and MD5) with the list.
function receiverCheck(key, listText, tagHex, receivedFiles) {
  const hmacOk = sameHex(toHex(hmacSha256(key, Buffer.from(listText))), tagHex);
  const list = JSON.parse(listText);
  const shares = receivedFiles.map((f, i) => {
    const got = digestsOf(f), saved = list["share" + (i + 1)];
    return { sha256Ok: got.sha256 === saved.sha256, md5Ok: got.md5 === saved.md5 };
  });
  return { hmacOk, shares, accepted: hmacOk && shares.every((s) => s.sha256Ok) };
}
function report(title, r) {
  console.log(`\n--- ${title}`);
  console.log(`    HMAC on digest list : ${r.hmacOk ? "valid" : "INVALID"}`);
  r.shares.forEach((s, i) => console.log(`    Share ${i + 1}: SHA-256 ${s.sha256Ok ? "match" : "DIFFERENT"}   MD5 ${s.md5Ok ? "match" : "DIFFERENT"}`));
  console.log(`    RESULT: ${r.accepted ? "ACCEPTED -> safe to stack the shares" : "REJECTED -> do not stack"}`);
}
function parseArgs() {
  const a = { file: null, mode: "visual", max: 300, gamma: 1 };
  for (const s of process.argv.slice(2)) {
    if (s.startsWith("--mode=")) a.mode = s.slice(7);
    else if (s.startsWith("--max=")) a.max = Number(s.slice(6));
    else if (s.startsWith("--gamma=")) a.gamma = Number(s.slice(8));
    else a.file = s;
  }
  if (!MODES[a.mode]) throw new Error('--mode must be "visual" or "xor"');
  return a;
}

function main() {
  const opt = parseArgs(), mode = MODES[opt.mode];

  // STEP 0: prove our hash code is correct by comparing it with Node's own crypto
  for (const n of [...Array(130).keys(), 1000, 65537]) {
    const m = crypto.randomBytes(n), k = crypto.randomBytes(n % 90 + 1);
    if (md5Hex(m) !== crypto.createHash("md5").update(m).digest("hex")) throw new Error("MD5 wrong");
    if (sha256Hex(m) !== crypto.createHash("sha256").update(m).digest("hex")) throw new Error("SHA-256 wrong");
    if (toHex(hmacSha256(k, m)) !== crypto.createHmac("sha256", k).update(m).digest("hex")) throw new Error("HMAC wrong");
  }
  console.log("STEP 0  MD5, SHA-256 and HMAC written from scratch match Node crypto (132 test sizes).");

  // STEP 1: the secret picture, in full colour
  let img;
  if (opt.file) { img = decodeImage(fs.readFileSync(opt.file), opt.file); const big = img.W + "x" + img.H; img = resize(img.rgb, img.W, img.H, opt.max);
    console.log(`STEP 1  Colour picture loaded from ${opt.file} (${big}) -> working size ${img.W} x ${img.H}.`); }
  else { img = { rgb: demoPicture(200, 150), W: 200, H: 150 }; console.log("STEP 1  Built-in colour picture: 200 x 150 pixels."); }
  const { rgb: secret, W: w, H: h } = img;

  // STEP 2: split into two shares
  const { s1, s2, SW, SH } = mode.shares(secret, w, h, opt.gamma);
  console.log(`STEP 2  Mode "${opt.mode}": two colour shares of ${SW} x ${SH} pixels.`);

  // STEP 3: save the shares as PNG files; these exact bytes are what we hash and send
  fs.mkdirSync("out", { recursive: true });
  const f1 = encodePng(s1, SW, SH), f2 = encodePng(s2, SW, SH);
  fs.writeFileSync("out/secret.png", encodePng(secret, w, h));
  fs.writeFileSync("out/share1.png", f1);
  fs.writeFileSync("out/share2.png", f2);
  console.log(`STEP 3  Saved out/share1.png (${f1.length} bytes) and out/share2.png (${f2.length} bytes).`);

  // STEP 4: sender hashes each saved share file with MD5 and SHA-256
  const list = { share1: digestsOf(f1), share2: digestsOf(f2) };
  console.log("STEP 4  Digests of the saved share files:");
  console.log("        share1 MD5    :", list.share1.md5);
  console.log("        share1 SHA-256:", list.share1.sha256);
  console.log("        share2 MD5    :", list.share2.md5);
  console.log("        share2 SHA-256:", list.share2.sha256);

  // STEP 5: protect the digest list with HMAC-SHA-256 (the key is known only to sender and receiver)
  const key = crypto.randomBytes(32);
  const listText = JSON.stringify(list);
  const tag = toHex(hmacSha256(key, Buffer.from(listText)));
  fs.writeFileSync("out/digests.json", JSON.stringify({ mode: opt.mode, list, hmacSha256: tag }, null, 2));
  console.log("STEP 5  HMAC-SHA-256 of the digest list:", tag);

  // STEP 6: receiver checks, then stacks only if everything matches
  console.log("\nSTEP 6  Receiver checks three situations:");
  const ok = receiverCheck(key, listText, tag, [f1, f2]);
  report("A. Shares arrive unchanged", ok);
  if (ok.accepted) {
    const stacked = mode.stack(s1, s2);
    fs.writeFileSync("out/stacked.png", encodePng(stacked, SW, SH));
    console.log("    Shares stacked -> out/stacked.png shows the colour picture.");
    if (opt.mode === "xor") console.log("    Exact colours recovered:", Buffer.compare(Buffer.from(stacked), Buffer.from(secret)) === 0);
  }

  // B. attacker changes ONE value inside Share 2 (invisible to the eye)
  report("B. Attacker changes ONE tiny part of Share 2", receiverCheck(key, listText, tag, [f1, encodePng(mode.tamper(s2), SW, SH)]));

  // C. attacker forges a Share 2 that shows a red cross, then also rewrites the digest list to match it
  const forged = mode.forge(s1, fakePicture(w, h), w, h), fForged = encodePng(forged, SW, SH);
  fs.writeFileSync("out/forged_share2.png", fForged);
  fs.writeFileSync("out/forged_stacked.png", encodePng(mode.stack(s1, forged), SW, SH));
  const fakeList = JSON.stringify({ share1: list.share1, share2: digestsOf(fForged) });
  report("C. Attacker forges Share 2 AND rewrites the digest list", receiverCheck(key, fakeList, tag, [f1, fForged]));
  console.log("    Note: the plain SHA-256 check passed (the attacker updated the digest). Only the HMAC caught it.");
}
main();