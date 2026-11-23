/*
 * receiver.js - RECEIVER side of the secure image flow
 *
 * Run first:
 *   node receiver.js
 *
 * Sender:
 *   node sender.js photo.png
 *
 * Options:
 *   --port=5000
 *   --host=127.0.0.1
 *   --key=<64 hex>
 *   --once
 *
 * Security additions:
 *   - HMAC-SHA-256 authenticates the complete canonical manifest.
 *   - Unique package IDs are recorded persistently to reject replayed packages.
 *   - ZIP structure, entry sizes, names and local/central headers are checked.
 *   - Incoming TCP message length and buffering are bounded.
 */

"use strict";

const path = require("path");
const net = require("net");
const C = require("./common.js");
const fs = require("fs");

// ============================================================================
// CONFIGURATION
// ============================================================================

const out = path.join(
  "runtime_output",
  "receiver"
);

const replayFile = path.join(
  out,
  "accepted_package_ids.txt"
);

const opt = {
  port: 5000,
  host: "127.0.0.1",
  key: null,
  once: false
};

for (const s of process.argv.slice(2)) {
  if (s.startsWith("--port=")) {
    opt.port = Number(s.slice(7));
  } else if (s.startsWith("--host=")) {
    opt.host = s.slice(7);
  } else if (s.startsWith("--key=")) {
    opt.key = s.slice(6);
  } else if (s === "--once") {
    opt.once = true;
  }
}

if (
  !Number.isInteger(opt.port) ||
  opt.port < 1 ||
  opt.port > 65535
) {
  throw new Error("Invalid --port");
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

class StageError extends Error {
  constructor(stage, message) {
    super(message);
    this.stage = stage;
  }
}

const fail = (stage, message) => {
  throw new StageError(stage, message);
};

const isHex = (s, n) =>
  typeof s === "string" &&
  new RegExp(`^[0-9a-f]{${n}}$`).test(s);

const log = (...a) => console.log(...a);

// ============================================================================
// REPLAY PROTECTION
// ============================================================================

function hasBeenAccepted(packageId) {
  if (!fs.existsSync(replayFile)) {
    return false;
  }

  const text = fs.readFileSync(
    replayFile,
    "utf8"
  );

  if (text && !text.endsWith("\n")) {
    fail(
      "replay-store",
      "Replay database has an incomplete final record; refusing to continue safely"
    );
  }

  const lines = text
    .split("\n")
    .filter(Boolean);

  for (const id of lines) {
    if (!isHex(id, 32)) {
      fail(
        "replay-store",
        "Replay database contains an invalid record"
      );
    }
  }

  return lines.includes(packageId);
}

function recordAccepted(packageId) {
  fs.appendFileSync(
    replayFile,
    packageId + "\n",
    {
      encoding: "utf8",
      flag: "a"
    }
  );
}

// ============================================================================
// PACKAGE PROCESSING
// ============================================================================

function processPackage(zipBytes) {
  const checks = {};

  // --------------------------------------------------------------------------
  // ZIP VALIDATION
  // --------------------------------------------------------------------------

  let files;

  try {
    files = C.zipRead(zipBytes);
  } catch (e) {
    fail("zip", e.message);
  }

  const names = Object.keys(files)
    .sort()
    .join(",");

  if (
    names !==
    "manifest.json,share_1.enc,share_2.enc"
  ) {
    fail(
      "zip",
      "Unexpected ZIP contents: " + names
    );
  }

  checks.zip = true;

  log(
    "  ZIP structure, names, CRCs and bounds verified."
  );

  // --------------------------------------------------------------------------
  // MANIFEST PARSING
  // --------------------------------------------------------------------------

  if (
    files["manifest.json"].length >
    64 * 1024
  ) {
    fail(
      "manifest",
      "Manifest exceeds 64 KiB"
    );
  }

  let mf;

  try {
    mf = JSON.parse(
      files["manifest.json"].toString("utf8")
    );
  } catch (_) {
    fail(
      "manifest",
      "manifest.json is not valid JSON"
    );
  }

  // --------------------------------------------------------------------------
  // MANIFEST FIELD VALIDATION
  // --------------------------------------------------------------------------

  const okInt = (v, max) =>
    Number.isSafeInteger(v) &&
    v > 0 &&
    v <= max;

  if (
    !mf ||
    mf.format !== "VCX-FLOW" ||
    mf.version !== 2
  ) {
    fail(
      "manifest",
      "Unsupported package format or version"
    );
  }

  if (!isHex(mf.package_id, 32)) {
    fail(
      "manifest",
      "Invalid package ID"
    );
  }

  if (
    typeof mf.created_at !== "string" ||
    Number.isNaN(Date.parse(mf.created_at))
  ) {
    fail(
      "manifest",
      "Invalid package creation time"
    );
  }

  if (
    !okInt(mf.width, 20000) ||
    !okInt(mf.height, 20000) ||
    mf.channels !== 3
  ) {
    fail(
      "manifest",
      "Invalid image dimensions or channel count"
    );
  }

  const pixelCount =
    mf.width * mf.height;

  const rgbLen =
    pixelCount * 3;

  if (
    !Number.isSafeInteger(rgbLen) ||
    rgbLen > C.MAX_PACKAGE ||
    mf.original_size !== rgbLen
  ) {
    fail(
      "manifest",
      "Image size in manifest does not match dimensions or exceeds limits"
    );
  }

  if (
    typeof mf.original_filename !== "string" ||
    mf.original_filename.length < 1 ||
    mf.original_filename.length > 255 ||
    path.basename(mf.original_filename) !== mf.original_filename ||
    /[\\/\0]/.test(mf.original_filename)
  ) {
    fail(
      "manifest",
      "Invalid file name"
    );
  }

  if (
    !isHex(mf.dynamic_nonce, 64) ||
    !isHex(mf.dynamic_digest, 64) ||
    !isHex(mf.hkdf_salt, 64) ||
    !isHex(mf.original_sha256, 64) ||
    !isHex(mf.original_md5, 32)
  ) {
    fail(
      "manifest",
      "Invalid hexadecimal field in manifest"
    );
  }

  if (
    mf.key_derivation !== "HKDF-SHA-256" ||
    mf.manifest_authentication !== "HMAC-SHA-256" ||
    mf.encryption !== "AES-256-GCM" ||
    mf.sharing !== "XOR-2-out-of-2"
  ) {
    fail(
      "manifest",
      "Unsupported cryptographic configuration"
    );
  }

  // --------------------------------------------------------------------------
  // RGB MEANS VALIDATION
  // --------------------------------------------------------------------------

  if (
    !mf.share_means ||
    !Array.isArray(mf.share_means.share_1) ||
    !Array.isArray(mf.share_means.share_2) ||
    mf.share_means.share_1.length !== 3 ||
    mf.share_means.share_2.length !== 3
  ) {
    fail(
      "manifest",
      "Invalid RGB means for the shares"
    );
  }

  for (
    const share of ["share_1", "share_2"]
  ) {
    for (const value of mf.share_means[share]) {
      if (
        typeof value !== "string" ||
        !/^\d+(\.\d{4})$/.test(value) ||
        Number(value) < 0 ||
        Number(value) > 255
      ) {
        fail(
          "manifest",
          `Invalid RGB mean in ${share}`
        );
      }
    }
  }

  // --------------------------------------------------------------------------
  // RANDOM SELECTION VALIDATION
  // --------------------------------------------------------------------------

  if (
    !mf.selection ||
    !Array.isArray(mf.selection.order) ||
    mf.selection.order.length !== 3 ||
    !Array.isArray(mf.selection.picks) ||
    mf.selection.picks.length !== 3 ||
    [...mf.selection.order].sort().join(",") !== "0,1,2" ||
    !mf.selection.picks.every(
      (v) =>
        Number.isInteger(v) &&
        v >= 0 &&
        v <= 255
    )
  ) {
    fail(
      "manifest",
      "Invalid random selection values"
    );
  }

  // --------------------------------------------------------------------------
  // ENCRYPTED SHARE SIZE VALIDATION
  // --------------------------------------------------------------------------

  if (
    !Number.isSafeInteger(mf.share_size) ||
    mf.share_size !== rgbLen + 16 ||
    files["share_1.enc"].length !== mf.share_size ||
    files["share_2.enc"].length !== mf.share_size
  ) {
    fail(
      "manifest",
      "Encrypted share length is wrong"
    );
  }

  checks.manifest = true;

  log(
    `  Manifest fields valid: ${mf.width} x ${mf.height}; package ${mf.package_id}.`
  );

  // --------------------------------------------------------------------------
  // LOAD MASTER SECRET
  // --------------------------------------------------------------------------

  let master;
  let where;

  try {
    ({
      master,
      where
    } = C.loadMaster(opt.key, false));
  } catch (e) {
    fail("key", e.message);
  }

  const salt = Buffer.from(
    mf.hkdf_salt,
    "hex"
  );

  // --------------------------------------------------------------------------
  // MANIFEST HMAC VERIFICATION
  // --------------------------------------------------------------------------

  if (
    !C.verifyManifestMac(
      master,
      salt,
      mf
    )
  ) {
    fail(
      "manifest-hmac",
      "Manifest HMAC is invalid; manifest may have been modified or the key is incorrect"
    );
  }

  checks.manifest_hmac = true;

  log(
    "  Manifest HMAC-SHA-256 verified."
  );

  // --------------------------------------------------------------------------
  // REPLAY CHECK
  // --------------------------------------------------------------------------

  if (
    hasBeenAccepted(mf.package_id)
  ) {
    fail(
      "replay",
      "This authenticated package ID has already been accepted"
    );
  }

  checks.replay_protection = true;

  // --------------------------------------------------------------------------
  // DYNAMIC SHA-256 VERIFICATION
  // --------------------------------------------------------------------------

  const digest = C.dynamicDigest(
    mf.share_means,
    mf.selection,
    mf.dynamic_nonce
  );

  if (digest !== mf.dynamic_digest) {
    fail(
      "digest",
      "Dynamic SHA-256 digest does not match the authenticated manifest"
    );
  }

  checks.digest = true;

  log(
    "  Dynamic SHA-256 digest verified:",
    digest
  );

  // --------------------------------------------------------------------------
  // HKDF KEY DERIVATION
  // --------------------------------------------------------------------------

  const k = C.deriveKeys(
    master,
    salt,
    mf.dynamic_digest
  );

  log(
    `  Master secret loaded from ${where}; HKDF-SHA-256 keys derived.`
  );

  // --------------------------------------------------------------------------
  // AES-256-GCM DECRYPTION
  // --------------------------------------------------------------------------

  let d1;
  let d2;

  try {
    d1 = C.aesDecrypt(
      k.key1,
      k.nonce1,
      C.shareAad(
        mf.original_filename,
        mf.width,
        mf.height,
        1
      ),
      files["share_1.enc"]
    );
  } catch (_) {
    fail(
      "aes-gcm",
      "Share 1 AES-GCM authentication failed"
    );
  }

  try {
    d2 = C.aesDecrypt(
      k.key2,
      k.nonce2,
      C.shareAad(
        mf.original_filename,
        mf.width,
        mf.height,
        2
      ),
      files["share_2.enc"]
    );
  } catch (_) {
    fail(
      "aes-gcm",
      "Share 2 AES-GCM authentication failed"
    );
  }

  if (
    d1.length !== rgbLen ||
    d2.length !== rgbLen
  ) {
    fail(
      "aes-gcm",
      "Decrypted share has the wrong length"
    );
  }

  checks.aes_gcm_tags = true;

  log(
    "  AES-256-GCM tags valid for both shares."
  );

  // --------------------------------------------------------------------------
  // RGB MEAN VERIFICATION
  // --------------------------------------------------------------------------

  const receivedMeans1 = C.rgbMeans(d1);
  const receivedMeans2 = C.rgbMeans(d2);

  const share1Match =
    receivedMeans1.join() ===
    mf.share_means.share_1.join();

  const share2Match =
    receivedMeans2.join() ===
    mf.share_means.share_2.join();

  if (!share1Match || !share2Match) {
    fail(
      "share-means",
      "RGB means of decrypted shares do not match the authenticated manifest"
    );
  }

  checks.share_mean_verification = true;

  log(
    "  Share 1 and Share 2 RGB means: MATCH."
  );

  // --------------------------------------------------------------------------
  // XOR IMAGE RECONSTRUCTION
  // --------------------------------------------------------------------------

  const rec = C.xorStack(
    new Uint8Array(d1),
    new Uint8Array(d2)
  );

  // --------------------------------------------------------------------------
  // ORIGINAL SHA-256 VERIFICATION
  // --------------------------------------------------------------------------

  const recSha = C.sha256Hex(rec);
  const recMd5 = C.md5Hex(rec);

  if (recSha !== mf.original_sha256) {
    fail(
      "sha256",
      "SHA-256 of the reconstructed image differs from the authenticated original hash"
    );
  }

  checks.sha256 = true;

  log(
    "  Reconstructed image SHA-256 matches:",
    recSha
  );

  log(
    "  Reconstructed image MD5:",
    recMd5,
    recMd5 === mf.original_md5
      ? "(matches)"
      : "(different; informational only)"
  );

  // --------------------------------------------------------------------------
  // SAVE ACCEPTED PACKAGE ID
  // --------------------------------------------------------------------------

  try {
    recordAccepted(mf.package_id);
  } catch (e) {
    fail(
      "replay-store",
      "Could not persist accepted package ID: " + e.message
    );
  }

  // --------------------------------------------------------------------------
  // SAVE RECONSTRUCTED FILES
  // --------------------------------------------------------------------------

  fs.writeFileSync(
    path.join(out, "decrypted_share_1.png"),
    C.encodePng(
      new Uint8Array(d1),
      mf.width,
      mf.height
    )
  );

  fs.writeFileSync(
    path.join(out, "decrypted_share_2.png"),
    C.encodePng(
      new Uint8Array(d2),
      mf.width,
      mf.height
    )
  );

  fs.writeFileSync(
    path.join(out, "reconstructed_image.png"),
    C.encodePng(
      rec,
      mf.width,
      mf.height
    )
  );

  // --------------------------------------------------------------------------
  // VERIFICATION REPORT
  // --------------------------------------------------------------------------

  const report = {
    status: "SUCCESS",

    checks,

    package_id: mf.package_id,

    original_filename: mf.original_filename,

    width: mf.width,
    height: mf.height,

    share_means: {
      share_1: {
        sender: mf.share_means.share_1,
        receiver: receivedMeans1,
        match: share1Match
      },

      share_2: {
        sender: mf.share_means.share_2,
        receiver: receivedMeans2,
        match: share2Match
      }
    },

    original_sha256: mf.original_sha256,
    reconstructed_sha256: recSha,
    reconstructed_md5: recMd5,

    md5_match: recMd5 === mf.original_md5
  };

  fs.writeFileSync(
    path.join(out, "verification_report.json"),
    JSON.stringify(report, null, 2)
  );

  return report;
}

// ============================================================================
// SEND RESPONSE TO SENDER
// ============================================================================

const send = (sock, obj) =>
  new Promise((resolve, reject) => {
    const bytes = C.lengthPrefix(
      Buffer.from(
        JSON.stringify(obj),
        "utf8"
      )
    );

    sock.write(bytes, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });

// ============================================================================
// START RECEIVER SERVER
// ============================================================================

fs.mkdirSync(
  out,
  { recursive: true }
);

// The receiver does not automatically create a master key.
// Sender and receiver must share the same secret.

let busy = false;

const server = net.createServer(
  async (sock) => {
    sock.setTimeout(
      60000,
      () => sock.destroy()
    );

    sock.on("error", () => {});

    if (busy) {
      try {
        await send(sock, {
          status: "FAILURE",
          stage: "busy",
          message: "receiver is busy",
          checks: {}
        });
      } catch (_) {}

      sock.end();
      return;
    }

    busy = true;

    const reader = new C.Reader(
      sock,
      C.MAX_PACKAGE + 8
    );

    let reply;

    try {
      log(
        "\n" +
        "=".repeat(70) +
        "\nRECEIVER: connection from " +
        sock.remoteAddress
      );

      // Read 8-byte package length
      const lenBig = (
        await reader.take(8)
      ).readBigUInt64BE();

      if (
        lenBig <= 0n ||
        lenBig > BigInt(C.MAX_PACKAGE)
      ) {
        fail(
          "length",
          "Invalid package length: " +
          lenBig.toString()
        );
      }

      const len = Number(lenBig);

      log(
        "STAGE 1  Package length:",
        len,
        "bytes"
      );

      // Read complete ZIP package
      const pkg = await reader.take(len);

      log(
        "STAGE 2  Package received completely."
      );

      // Process and verify package
      reply = processPackage(pkg);

      log(
        "RESULT   SUCCESS: package accepted. Files saved in",
        out
      );
    } catch (e) {
      log(
        `RESULT   REJECTED at "${e.stage || "network"}": ${e.message}`
      );

      reply = {
        status: "FAILURE",
        stage: e.stage || "network",
        message: e.message,
        checks: {}
      };
    }

    // Send result to sender
    try {
      await send(sock, reply);
    } catch (_) {}

    sock.end();

    busy = false;

    if (opt.once) {
      server.close();
    }
  }
);

// ============================================================================
// LISTEN
// ============================================================================

server.listen(
  opt.port,
  opt.host,
  () => {
    console.log(
      `RECEIVER listening on ${opt.host}:${opt.port} (press Ctrl+C to stop)`
    );

    console.log(
      `Replay database: ${replayFile}`
    );
  }
);

server.on("error", (e) => {
  console.error(
    "RECEIVER ERROR:",
    e.message
  );

  process.exit(1);
});