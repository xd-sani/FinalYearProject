/*
 * common.js - shared tools for sender.js and receiver.js
 *
 * Hashes written from scratch:
 * MD5, SHA-256, HMAC-SHA-256, HKDF-SHA-256
 *
 * AES-256-GCM: Node.js built-in crypto
 * PNG / BMP reading, PNG writing, XOR secret sharing,
 * ZIP writer/reader, TCP message reader.
 *
 * JPG files require: npm install jpeg-js
 */

"use strict";

const fs = require("fs");
const zlib = require("zlib");
const crypto = require("crypto");

// ============================================================================
// PART 1. HASH FUNCTIONS FROM SCRATCH
// ============================================================================

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

const toHex = (bytes) => Buffer.from(bytes).toString("hex");

const concat = (...parts) =>
  Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));

// Padding
function pad(data, littleEndian) {
  const n = data.length;

  const total =
    n + 1 + (((55 - n) % 64 + 64) % 64) + 8;

  const out = new Uint8Array(total);

  out.set(data);
  out[n] = 0x80;

  new DataView(out.buffer).setBigUint64(
    total - 8,
    BigInt(n) * 8n,
    littleEndian
  );

  return out;
}

// ============================================================================
// MD5
// ============================================================================

const MD5_SHIFT = [
  ...Array(4).fill([7, 12, 17, 22]).flat(),
  ...Array(4).fill([5, 9, 14, 20]).flat(),
  ...Array(4).fill([4, 11, 16, 23]).flat(),
  ...Array(4).fill([6, 10, 15, 21]).flat(),
];

const MD5_K = Array.from(
  { length: 64 },
  (_, i) =>
    Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0
);

function md5(data) {
  const msg = pad(data, true);
  const view = new DataView(msg.buffer);

  const M = new Uint32Array(16);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      M[i] = view.getUint32(off + i * 4, true);
    }

    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      let F;
      let g;

      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }

      F = (F + A + MD5_K[i] + M[g]) >>> 0;

      A = D;
      D = C;
      C = B;

      B = (B + rotl(F, MD5_SHIFT[i])) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new DataView(new ArrayBuffer(16));

  [a0, b0, c0, d0].forEach((v, i) => {
    out.setUint32(i * 4, v, true);
  });

  return new Uint8Array(out.buffer);
}

// ============================================================================
// SHA-256
// ============================================================================

const primes = (n) => {
  const p = [];

  for (let x = 2; p.length < n; x++) {
    if (p.every((q) => x % q)) {
      p.push(x);
    }
  }

  return p;
};

const icbrt = (n) => {
  let lo = 0n;

  let hi =
    1n << BigInt(Math.ceil(n.toString(2).length / 3) + 2);

  while (lo < hi) {
    const m = (lo + hi + 1n) / 2n;

    if (m ** 3n <= n) {
      lo = m;
    } else {
      hi = m - 1n;
    }
  }

  return lo;
};

const isqrt = (n) => {
  let x = BigInt(Math.floor(Math.sqrt(Number(n))));

  while (x * x > n) x--;

  while ((x + 1n) ** 2n <= n) x++;

  return x;
};

const PR = primes(64);

const SHA_H0 = PR.slice(0, 8).map(
  (p) =>
    Number(isqrt(BigInt(p) << 64n) & 0xffffffffn)
);

const SHA_K = PR.map(
  (p) =>
    Number(icbrt(BigInt(p) << 96n) & 0xffffffffn)
);

function sha256(data) {
  const msg = pad(data, false);

  const view = new DataView(msg.buffer);

  const H = Uint32Array.from(SHA_H0);
  const w = new Uint32Array(64);

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(off + i * 4, false);
    }

    for (let i = 16; i < 64; i++) {
      const s0 =
        rotr(w[i - 15], 7) ^
        rotr(w[i - 15], 18) ^
        (w[i - 15] >>> 3);

      const s1 =
        rotr(w[i - 2], 17) ^
        rotr(w[i - 2], 19) ^
        (w[i - 2] >>> 10);

      w[i] =
        (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];
    let f = H[5];
    let g = H[6];
    let h = H[7];

    for (let i = 0; i < 64; i++) {
      const S1 =
        rotr(e, 6) ^
        rotr(e, 11) ^
        rotr(e, 25);

      const ch = (e & f) ^ (~e & g);

      const t1 =
        (h + S1 + ch + SHA_K[i] + w[i]) >>> 0;

      const S0 =
        rotr(a, 2) ^
        rotr(a, 13) ^
        rotr(a, 22);

      const maj =
        (a & b) ^ (a & c) ^ (b & c);

      const t2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }

  const out = new DataView(new ArrayBuffer(32));

  H.forEach((v, i) => {
    out.setUint32(i * 4, v, false);
  });

  return new Uint8Array(out.buffer);
}

// ============================================================================
// HMAC-SHA-256
// ============================================================================

function hmacSha256(key, msg) {
  let k = Uint8Array.from(key);

  if (k.length > 64) {
    k = sha256(k);
  }

  const block = new Uint8Array(64);

  block.set(k);

  const inner = sha256(
    concat(
      block.map((b) => b ^ 0x36),
      msg
    )
  );

  return sha256(
    concat(
      block.map((b) => b ^ 0x5c),
      inner
    )
  );
}

const md5Hex = (d) => toHex(md5(d));
const sha256Hex = (d) => toHex(sha256(d));

const sameHex = (a, b) =>
  a.length === b.length &&
  crypto.timingSafeEqual(
    Buffer.from(a),
    Buffer.from(b)
  );

// ============================================================================
// HKDF-SHA-256
// ============================================================================

function hkdf(master, salt, info, length = 32) {
  const prk = hmacSha256(salt, master);

  const blocks = [];

  let t = new Uint8Array(0);

  for (let i = 1; blocks.length * 32 < length; i++) {
    t = hmacSha256(
      prk,
      concat(
        t,
        Buffer.from(info),
        Buffer.from([i])
      )
    );

    blocks.push(Buffer.from(t));
  }

  return Buffer.concat(blocks).subarray(0, length);
}

// ============================================================================
// PART 1B. AES-256-GCM
// ============================================================================

const MAGIC = Buffer.from("VCX1");

const HEADER_LEN = 4 + 32 + 12;
const TAG_LEN = 16;

const AES_INFO = "vc-share-aes-256-gcm-v1";
const MAC_INFO = "vc-digest-list-hmac-sha256-v1";

function encryptShare(master, label, plain) {
  const salt = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);

  const header = Buffer.concat([
    MAGIC,
    salt,
    nonce
  ]);

  const c = crypto.createCipheriv(
    "aes-256-gcm",
    hkdf(master, salt, AES_INFO),
    nonce
  );

  c.setAAD(
    Buffer.concat([
      header,
      Buffer.from(label)
    ])
  );

  const ct = Buffer.concat([
    c.update(plain),
    c.final()
  ]);

  return Buffer.concat([
    header,
    ct,
    c.getAuthTag()
  ]);
}

function decryptShare(master, label, blob) {
  if (
    blob.length < HEADER_LEN + TAG_LEN ||
    !blob.subarray(0, 4).equals(MAGIC)
  ) {
    return { ok: false };
  }

  const header = blob.subarray(0, HEADER_LEN);

  const salt = blob.subarray(4, 36);
  const nonce = blob.subarray(36, 48);

  try {
    const d = crypto.createDecipheriv(
      "aes-256-gcm",
      hkdf(master, salt, AES_INFO),
      nonce
    );

    d.setAAD(
      Buffer.concat([
        header,
        Buffer.from(label)
      ])
    );

    d.setAuthTag(
      blob.subarray(blob.length - TAG_LEN)
    );

    return {
      ok: true,
      data: Buffer.concat([
        d.update(
          blob.subarray(
            HEADER_LEN,
            blob.length - TAG_LEN
          )
        ),
        d.final()
      ])
    };
  } catch (e) {
    return { ok: false };
  }
}

// ============================================================================
// PART 2. PNG READ / WRITE
// ============================================================================

const CRC_TABLE = Array.from(
  { length: 256 },
  (_, n) => {
    let c = n;

    for (let k = 0; k < 8; k++) {
      c =
        c & 1
          ? 0xedb88320 ^ (c >>> 1)
          : c >>> 1;
    }

    return c >>> 0;
  }
);

const crc32 = (buf) => {
  let c = 0xffffffff;

  for (const b of buf) {
    c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  }

  return (c ^ 0xffffffff) >>> 0;
};

function chunk(type, data) {
  const len = Buffer.alloc(4);

  len.writeUInt32BE(data.length);

  const td = Buffer.concat([
    Buffer.from(type),
    data
  ]);

  const crc = Buffer.alloc(4);

  crc.writeUInt32BE(crc32(td));

  return Buffer.concat([
    len,
    td,
    crc
  ]);
}

function encodePng(rgb, W, H) {
  const raw = Buffer.alloc((W * 3 + 1) * H);

  for (let y = 0; y < H; y++) {
    Buffer.from(
      rgb.buffer,
      rgb.byteOffset + y * W * 3,
      W * 3
    ).copy(
      raw,
      y * (W * 3 + 1) + 1
    );
  }

  const ihdr = Buffer.alloc(13);

  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);

  ihdr[8] = 8;
  ihdr[9] = 2;

  return Buffer.concat([
    Buffer.from([
      137, 80, 78, 71, 13, 10, 26, 10
    ]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0))
  ]);
}

// ============================================================================
// PNG DECODING
// ============================================================================

function decodePng(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) {
    throw new Error("This is not a PNG file");
  }

  let pos = 8;

  let W;
  let H;
  let depth;
  let ctype;
  let interlace;

  let plte = null;
  let trns = null;

  const idat = [];

  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);

    const type = buf.toString(
      "ascii",
      pos + 4,
      pos + 8
    );

    const data = buf.subarray(
      pos + 8,
      pos + 8 + len
    );

    if (type === "IHDR") {
      W = data.readUInt32BE(0);
      H = data.readUInt32BE(4);

      depth = data[8];
      ctype = data[9];
      interlace = data[12];
    }

    if (type === "PLTE") plte = data;
    if (type === "tRNS") trns = data;
    if (type === "IDAT") idat.push(data);

    pos += 12 + len;
  }

  if (interlace) {
    throw new Error(
      "Interlaced PNG is not supported. Re-save the image as a normal PNG."
    );
  }

  if (
    ![1, 2, 4, 8, 16].includes(depth) ||
    (depth < 8 && ctype !== 0 && ctype !== 3)
  ) {
    throw new Error(
      `${depth}-bit PNG of this type is not supported.`
    );
  }

  const ch = {
    0: 1,
    2: 3,
    3: 1,
    4: 2,
    6: 4
  }[ctype];

  const bps = Math.max(depth, 8) / 8;
  const bpp = ch * bps;

  const stride = Math.ceil(
    W * ch * depth / 8
  );

  const raw = zlib.inflateSync(
    Buffer.concat(idat)
  );

  const px = Buffer.alloc(stride * H);

  // Undo PNG filters
  for (let y = 0; y < H; y++) {
    const ft = raw[y * (stride + 1)];

    for (let i = 0; i < stride; i++) {
      const cur = raw[
        y * (stride + 1) + 1 + i
      ];

      const a =
        i >= bpp
          ? px[y * stride + i - bpp]
          : 0;

      const b =
        y
          ? px[(y - 1) * stride + i]
          : 0;

      const c =
        y && i >= bpp
          ? px[(y - 1) * stride + i - bpp]
          : 0;

      let v = cur;

      if (ft === 1) {
        v += a;
      } else if (ft === 2) {
        v += b;
      } else if (ft === 3) {
        v += (a + b) >> 1;
      } else if (ft === 4) {
        const p = a + b - c;

        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);

        v +=
          pa <= pb && pa <= pc
            ? a
            : pb <= pc
              ? b
              : c;
      }

      px[y * stride + i] = v & 255;
    }
  }

  const rgb = new Uint8Array(W * H * 3);

  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const i = y * W + x;
      const base = y * stride;

      let r;
      let g;
      let b;
      let a = 255;

      if (depth < 8) {
        const bit = x * depth;

        const v =
          (px[base + (bit >> 3)] >>
            (8 - depth - (bit & 7))) &
          ((1 << depth) - 1);

        if (ctype === 0) {
          r = g = b = Math.round(
            v * 255 / ((1 << depth) - 1)
          );
        } else {
          r = plte[v * 3];
          g = plte[v * 3 + 1];
          b = plte[v * 3 + 2];

          if (trns && v < trns.length) {
            a = trns[v];
          }
        }
      } else {
        const s = (k) =>
          px[base + x * bpp + k * bps];

        if (ctype === 0) {
          r = g = b = s(0);
        } else if (ctype === 2) {
          r = s(0);
          g = s(1);
          b = s(2);
        } else if (ctype === 3) {
          const p = s(0);

          r = plte[p * 3];
          g = plte[p * 3 + 1];
          b = plte[p * 3 + 2];

          if (trns && p < trns.length) {
            a = trns[p];
          }
        } else if (ctype === 4) {
          r = g = b = s(0);
          a = s(1);
        } else {
          r = s(0);
          g = s(1);
          b = s(2);
          a = s(3);
        }
      }

      rgb[i * 3] =
        (r * a + 255 * (255 - a)) / 255;

      rgb[i * 3 + 1] =
        (g * a + 255 * (255 - a)) / 255;

      rgb[i * 3 + 2] =
        (b * a + 255 * (255 - a)) / 255;
    }
  }

  return { rgb, W, H };
}

// ============================================================================
// BMP DECODING
// ============================================================================

function decodeBmp(buf) {
  const off = buf.readUInt32LE(10);
  const W = buf.readInt32LE(18);

  let H = buf.readInt32LE(22);

  const bpp = buf.readUInt16LE(28);
  const comp = buf.readUInt32LE(30);

  if (
    (bpp !== 24 && bpp !== 32) ||
    comp !== 0
  ) {
    throw new Error(
      "This BMP is not a plain 24/32-bit BMP. Save it as PNG."
    );
  }

  const topDown = H < 0;

  H = Math.abs(H);

  const stride =
    Math.floor((bpp * W + 31) / 32) * 4;

  const px = bpp / 8;

  const rgb = new Uint8Array(W * H * 3);

  for (let y = 0; y < H; y++) {
    const row =
      off + (topDown ? y : H - 1 - y) * stride;

    for (let x = 0; x < W; x++) {
      const p = row + x * px;
      const o = (y * W + x) * 3;

      rgb[o] = buf[p + 2];
      rgb[o + 1] = buf[p + 1];
      rgb[o + 2] = buf[p];
    }
  }

  return { rgb, W, H };
}

// ============================================================================
// IMAGE DECODING
// ============================================================================

function decodeImage(buf, name) {
  if (
    buf.length > 8 &&
    buf.readUInt32BE(0) === 0x89504e47
  ) {
    return decodePng(buf);
  }

  // JPEG
  if (
    buf.length > 3 &&
    buf[0] === 0xff &&
    buf[1] === 0xd8 &&
    buf[2] === 0xff
  ) {
    let jpeg;

    try {
      jpeg = require("jpeg-js");
    } catch (e) {
      throw new Error(
        `${name} is a JPG file. Run npm install jpeg-js or convert it to PNG.`
      );
    }

    const {
      data,
      width: W,
      height: H
    } = jpeg.decode(buf, {
      useTArray: true,
      formatAsRGBA: true
    });

    const rgb = new Uint8Array(W * H * 3);

    for (let i = 0; i < W * H; i++) {
      for (let c = 0; c < 3; c++) {
        rgb[i * 3 + c] = data[i * 4 + c];
      }
    }

    return { rgb, W, H };
  }

  // BMP
  if (
    buf.length > 30 &&
    buf[0] === 0x42 &&
    buf[1] === 0x4d
  ) {
    return decodeBmp(buf);
  }

  throw new Error(
    `${name} is not a PNG, JPG or BMP picture.`
  );
}

// ============================================================================
// IMAGE RESIZE
// ============================================================================

function resize(rgb, W, H, maxSide) {
  if (
    !maxSide ||
    Math.max(W, H) <= maxSide
  ) {
    return { rgb, W, H };
  }

  const sc = maxSide / Math.max(W, H);

  const nw = Math.max(1, Math.round(W * sc));
  const nh = Math.max(1, Math.round(H * sc));

  const out = new Uint8Array(nw * nh * 3);

  for (let y = 0; y < nh; y++) {
    for (let x = 0; x < nw; x++) {
      const x0 = Math.floor(x / sc);

      const x1 = Math.min(
        W,
        Math.max(x0 + 1, Math.ceil((x + 1) / sc))
      );

      const y0 = Math.floor(y / sc);

      const y1 = Math.min(
        H,
        Math.max(y0 + 1, Math.ceil((y + 1) / sc))
      );

      const sum = [0, 0, 0];

      let n = 0;

      for (let yy = y0; yy < y1; yy++) {
        for (let xx = x0; xx < x1; xx++) {
          for (let c = 0; c < 3; c++) {
            sum[c] +=
              rgb[(yy * W + xx) * 3 + c];
          }

          n++;
        }
      }

      for (let c = 0; c < 3; c++) {
        out[(y * nw + x) * 3 + c] =
          Math.round(sum[c] / n);
      }
    }
  }

  return {
    rgb: out,
    W: nw,
    H: nh
  };
}

// ============================================================================
// PART 3. COLOUR VISUAL CRYPTOGRAPHY
// ============================================================================

const PATTERNS = [
  [1, 1, 0, 0],
  [0, 0, 1, 1],
  [1, 0, 1, 0],
  [0, 1, 0, 1],
  [1, 0, 0, 1],
  [0, 1, 1, 0]
];

// Floyd-Steinberg halftoning
function halftone(rgb, c, w, h, gamma = 1) {
  const v = new Float32Array(w * h);
  const dark = new Uint8Array(w * h);

  for (let i = 0; i < w * h; i++) {
    v[i] =
      255 * Math.pow(rgb[i * 3 + c] / 255, gamma);
  }

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = y * w + x;

      const old = v[i];

      const nw = old < 128 ? 0 : 255;

      const err = old - nw;

      dark[i] = nw === 0 ? 1 : 0;

      if (x + 1 < w) {
        v[i + 1] += err * 7 / 16;
      }

      if (y + 1 < h) {
        if (x > 0) {
          v[i + w - 1] += err * 3 / 16;
        }

        v[i + w] += err * 5 / 16;

        if (x + 1 < w) {
          v[i + w + 1] += err / 16;
        }
      }
    }
  }

  return dark;
}

function visualShares(rgb, w, h, gamma = 1) {
  const SW = w * 2;
  const SH = h * 2;

  const s1 = new Uint8Array(SW * SH * 3);
  const s2 = new Uint8Array(SW * SH * 3);

  for (let c = 0; c < 3; c++) {
    const dark = halftone(rgb, c, w, h, gamma);

    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const p = PATTERNS[crypto.randomInt(6)];

        for (let k = 0; k < 4; k++) {
          const idx =
            (2 * y + (k >> 1)) * SW +
            2 * x +
            (k & 1);

          const q = dark[y * w + x]
            ? 1 - p[k]
            : p[k];

          s1[idx * 3 + c] =
            p[k] ? 0 : 255;

          s2[idx * 3 + c] =
            q ? 0 : 255;
        }
      }
    }
  }

  return {
    s1,
    s2,
    SW,
    SH
  };
}

// Visual stacking
const visualStack = (a, b) =>
  a.map((v, i) =>
    v === 0 || b[i] === 0 ? 0 : 255
  );

// Visual forging
function visualForge(s1, fakeRgb, w, h) {
  const SW = w * 2;

  const out = new Uint8Array(s1.length);

  for (let c = 0; c < 3; c++) {
    const dark = halftone(fakeRgb, c, w, h);

    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        for (let k = 0; k < 4; k++) {
          const idx =
            (2 * y + (k >> 1)) * SW +
            2 * x +
            (k & 1);

          const p =
            s1[idx * 3 + c] === 0 ? 1 : 0;

          out[idx * 3 + c] =
            (dark[y * w + x] ? 1 - p : p)
              ? 0
              : 255;
        }
      }
    }
  }

  return out;
}

// ============================================================================
// XOR SECRET SHARING
// ============================================================================

function xorShares(rgb, w, h) {
  const s1 = crypto.randomBytes(rgb.length);

  const s2 = new Uint8Array(rgb.length);

  for (let i = 0; i < rgb.length; i++) {
    s2[i] = rgb[i] ^ s1[i];
  }

  return {
    s1: new Uint8Array(s1),
    s2,
    SW: w,
    SH: h
  };
}

const xorStack = (a, b) =>
  a.map((v, i) => v ^ b[i]);

const xorForge = (s1, fakeRgb) =>
  Uint8Array.from(
    fakeRgb,
    (v, i) => v ^ s1[i]
  );

// ============================================================================
// MODES
// ============================================================================

const MODES = {
  visual: {
    shares: visualShares,
    stack: visualStack,

    forge: (s1, fake, w, h) =>
      visualForge(s1, fake, w, h),

    tamper: (s) => {
      const t = s.slice();

      const i = Math.floor(t.length / 2);

      t[i] = t[i] === 0 ? 255 : 0;

      return t;
    }
  },

  xor: {
    shares: xorShares,
    stack: xorStack,

    forge: (s1, fake) =>
      xorForge(s1, fake),

    tamper: (s) => {
      const t = s.slice();

      t[Math.floor(t.length / 2)] ^= 1;

      return t;
    }
  }
};

// ============================================================================
// BUILT-IN DEMO PICTURE
// ============================================================================

function demoPicture(w, h) {
  const rgb = new Uint8Array(w * h * 3);

  const lerp = (a, b, t) =>
    Math.round(a + (b - a) * t);

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const t = y / h;

      let c = [
        lerp(40, 255, t),
        lerp(100, 175, t),
        lerp(215, 90, t)
      ];

      if (
        Math.hypot(
          x - w * 0.72,
          y - h * 0.3
        ) < h * 0.14
      ) {
        c = [255, 225, 60];
      }

      if (
        y > h * 0.68 + 8 * Math.sin(x / 16)
      ) {
        c = [30, 130, 55];
      }

      if (y > h * 0.8) {
        c = [20, 95, 150];
      }

      if (
        x > w * 0.18 &&
        x < w * 0.38 &&
        y > h * 0.5 &&
        y < h * 0.72
      ) {
        c = [200, 40, 40];
      }

      if (
        y > h * 0.36 &&
        y <= h * 0.5 &&
        Math.abs(x - w * 0.28) <
          (y - h * 0.36) * 1.3
      ) {
        c = [120, 70, 30];
      }

      rgb.set(c, (y * w + x) * 3);
    }
  }

  return rgb;
}

function fakePicture(w, h) {
  const rgb = new Uint8Array(w * h * 3).fill(255);

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const xs = x * h / w;

      if (
        Math.abs(xs - y) < 8 ||
        Math.abs(xs - (h - 1 - y)) < 8
      ) {
        rgb.set(
          [225, 20, 20],
          (y * w + x) * 3
        );
      }
    }
  }

  return rgb;
}

// ============================================================================
// PART A. FLOWCHART FUNCTIONS
// ============================================================================

const CHANNELS = "RGB";

const MAX_PACKAGE = 250 * 1024 * 1024;

// RGB MEAN CALCULATION
function rgbMeans(rgb) {
  const sum = [0, 0, 0];

  const n = rgb.length / 3;

  for (let i = 0; i < rgb.length; i += 3) {
    sum[0] += rgb[i];
    sum[1] += rgb[i + 1];
    sum[2] += rgb[i + 2];
  }

  return sum.map(
    (v) => (v / n).toFixed(4)
  );
}

// RANDOM SELECTION
function randomSelection() {
  const order = [0, 1, 2];

  for (let i = order.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);

    [order[i], order[j]] =
      [order[j], order[i]];
  }

  return {
    order,
    picks: [
      crypto.randomInt(256),
      crypto.randomInt(256),
      crypto.randomInt(256)
    ]
  };
}

// DYNAMIC SHA-256 DIGEST
function dynamicDigest(means, selection, nonceHex) {
  return sha256Hex(
    Buffer.from(
      JSON.stringify({
        means,
        selection,
        nonce: nonceHex
      })
    )
  );
}

// HKDF KEY DERIVATION
function deriveKeys(master, salt, digestHex) {
  const okm = hkdf(
    master,
    salt,
    "vcx-flow-v1|" + digestHex,
    32 + 32 + 12 + 12
  );

  return {
    key1: okm.subarray(0, 32),
    key2: okm.subarray(32, 64),
    nonce1: okm.subarray(64, 76),
    nonce2: okm.subarray(76, 88)
  };
}

// AES-GCM ASSOCIATED DATA
const shareAad = (name, W, H, n) =>
  Buffer.from(
    JSON.stringify({
      name,
      W,
      H,
      share: n
    })
  );

// AES ENCRYPTION
function aesEncrypt(key, nonce, aad, plain) {
  const c = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    nonce
  );

  c.setAAD(aad);

  const ct = Buffer.concat([
    c.update(plain),
    c.final()
  ]);

  return Buffer.concat([
    ct,
    c.getAuthTag()
  ]);
}

// AES DECRYPTION
function aesDecrypt(key, nonce, aad, blob) {
  if (blob.length < 16) {
    throw new Error("encrypted share too short");
  }

  const d = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    nonce
  );

  d.setAAD(aad);

  d.setAuthTag(
    blob.subarray(blob.length - 16)
  );

  return Buffer.concat([
    d.update(
      blob.subarray(0, blob.length - 16)
    ),
    d.final()
  ]);
}

// ============================================================================
// MASTER SECRET
// ============================================================================

function loadMaster(
  hexFromArg,
  createIfMissing,
  file = "master.key"
) {
  if (hexFromArg) {
    if (!/^[0-9a-fA-F]{64}$/.test(hexFromArg)) {
      throw new Error(
        "--key must be 64 hex characters (256 bits)"
      );
    }

    return {
      master: Buffer.from(hexFromArg, "hex"),
      created: false,
      where: "--key"
    };
  }

  if (fs.existsSync(file)) {
    const hex = fs.readFileSync(
      file,
      "utf8"
    ).trim();

    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error(
        `${file} is not a 64-hex-character key`
      );
    }

    return {
      master: Buffer.from(hex, "hex"),
      created: false,
      where: file
    };
  }

  if (!createIfMissing) {
    throw new Error(
      `Master secret not found (${file}). Run the sender first, or copy master.key here.`
    );
  }

  const master = crypto.randomBytes(32);

  fs.writeFileSync(
    file,
    master.toString("hex")
  );

  return {
    master,
    created: true,
    where: file
  };
}

// ============================================================================
// ZIP WRITER
// ============================================================================

function zipWrite(entries) {
  const locals = [];
  const centrals = [];

  let offset = 0;

  for (const e of entries) {
    const name = Buffer.from(e.name);
    const data = Buffer.from(e.data);

    const crc = crc32(data);

    const lh = Buffer.alloc(30);

    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0x21, 12);

    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);

    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);

    const ch = Buffer.alloc(46);

    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0x21, 14);

    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);

    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);

    locals.push(lh, name, data);
    centrals.push(ch, name);

    offset += 30 + name.length + data.length;
  }

  const cd = Buffer.concat(centrals);

  const end = Buffer.alloc(22);

  end.writeUInt32LE(0x06054b50, 0);

  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);

  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([
    ...locals,
    cd,
    end
  ]);
}

// ============================================================================
// ZIP READER
// ============================================================================

function zipRead(buf) {
  const bad = (why) =>
    new Error("ZIP package is damaged: " + why);

  let eocd = -1;

  for (
    let i = buf.length - 22;
    i >= Math.max(0, buf.length - 22 - 65535);
    i--
  ) {
    if (
      buf.readUInt32LE(i) === 0x06054b50
    ) {
      eocd = i;
      break;
    }
  }

  if (eocd < 0) {
    throw bad("end record not found");
  }

  const count = buf.readUInt16LE(eocd + 10);

  let p = buf.readUInt32LE(eocd + 16);

  const files = {};

  for (let k = 0; k < count; k++) {
    if (
      p + 46 > buf.length ||
      buf.readUInt32LE(p) !== 0x02014b50
    ) {
      throw bad("bad directory entry");
    }

    const method = buf.readUInt16LE(p + 10);

    const crc = buf.readUInt32LE(p + 16);

    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);

    const nlen = buf.readUInt16LE(p + 28);
    const xlen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);

    const rel = buf.readUInt32LE(p + 42);

    const name = buf.subarray(
      p + 46,
      p + 46 + nlen
    ).toString("utf8");

    if (method !== 0 || csize !== usize) {
      throw bad(
        "only stored (uncompressed) entries are accepted"
      );
    }

    if (
      !/^[A-Za-z0-9_.-]+$/.test(name) ||
      name.includes("..") ||
      name in files
    ) {
      throw bad("unsafe or repeated file name");
    }

    if (
      rel + 30 > buf.length ||
      buf.readUInt32LE(rel) !== 0x04034b50
    ) {
      throw bad("bad local header");
    }

    const start =
      rel +
      30 +
      buf.readUInt16LE(rel + 26) +
      buf.readUInt16LE(rel + 28);

    if (start + csize > buf.length) {
      throw bad("entry runs past the end");
    }

    const data = buf.subarray(
      start,
      start + csize
    );

    if (crc32(data) !== crc) {
      throw bad("CRC-32 mismatch in " + name);
    }

    files[name] = Buffer.from(data);

    p += 46 + nlen + xlen + clen;
  }

  return files;
}

// ============================================================================
// TCP READER
// ============================================================================

class Reader {
  constructor(sock) {
    this.parts = [];
    this.len = 0;
    this.wake = null;
    this.ended = false;
    this.err = null;

    sock.on("data", (d) => {
      this.parts.push(d);
      this.len += d.length;
      this._go();
    });

    sock.on("end", () => {
      this.ended = true;
      this._go();
    });

    sock.on("close", () => {
      this.ended = true;
      this._go();
    });

    sock.on("error", (e) => {
      this.err = e;
      this._go();
    });
  }

  _go() {
    if (this.wake) {
      const w = this.wake;

      this.wake = null;

      w();
    }
  }

  async take(n) {
    while (this.len < n) {
      if (this.err) {
        throw this.err;
      }

      if (this.ended) {
        throw new Error(
          "connection closed before all data arrived"
        );
      }

      await new Promise((r) => {
        this.wake = r;
      });
    }

    const all = Buffer.concat(this.parts);

    const out = Buffer.from(
      all.subarray(0, n)
    );

    const rest = all.subarray(n);

    this.parts = rest.length ? [rest] : [];

    this.len = rest.length;

    return out;
  }
}

const lengthPrefix = (bytes) => {
  const h = Buffer.alloc(8);

  h.writeBigUInt64BE(
    BigInt(bytes.length)
  );

  return Buffer.concat([
    h,
    bytes
  ]);
};

// ============================================================================
// SELF TEST
// ============================================================================

function selfTest() {
  const sizes = [
    0,
    1,
    55,
    56,
    63,
    64,
    65,
    119,
    120,
    1000,
    4096,
    65537
  ];

  for (const n of sizes) {
    const m = crypto.randomBytes(n);

    const k = crypto.randomBytes(
      n % 90 + 1
    );

    const salt = crypto.randomBytes(
      n % 40
    );

    const info = "t" + n;

    if (
      md5Hex(m) !==
      crypto.createHash("md5")
        .update(m)
        .digest("hex")
    ) {
      throw new Error("MD5 self-test failed");
    }

    if (
      sha256Hex(m) !==
      crypto.createHash("sha256")
        .update(m)
        .digest("hex")
    ) {
      throw new Error("SHA-256 self-test failed");
    }

    if (
      toHex(hmacSha256(k, m)) !==
      crypto.createHmac("sha256", k)
        .update(m)
        .digest("hex")
    ) {
      throw new Error("HMAC self-test failed");
    }

    if (
      !hkdf(k, salt, info, 88).equals(
        Buffer.from(
          crypto.hkdfSync(
            "sha256",
            k,
            salt,
            info,
            88
          )
        )
      )
    ) {
      throw new Error("HKDF self-test failed");
    }
  }

  return sizes.length;
}

// ============================================================================
// MODULE EXPORTS
// ============================================================================

module.exports = {
  fs,
  crypto,

  md5Hex,
  sha256Hex,
  toHex,
  sameHex,

  hkdf,

  decodeImage,
  resize,
  encodePng,

  xorShares,
  xorStack,

  demoPicture,

  rgbMeans,
  randomSelection,
  dynamicDigest,

  deriveKeys,
  shareAad,

  aesEncrypt,
  aesDecrypt,

  loadMaster,

  zipWrite,
  zipRead,

  Reader,
  lengthPrefix,

  selfTest,

  MAX_PACKAGE,
  CHANNELS
};