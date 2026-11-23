/*
 * receiver.js - RECEIVER side of the flowchart
 *
 * Run FIRST:
 *   node receiver.js
 *
 * Then:
 *   node sender.js photo.png
 *
 * Options:
 *   --port=5000
 *   --key=<64 hex>
 *   --once
 *   --host=0.0.0.0
 */
"use strict";

const path = require("path");
const net = require("net");
const C = require("./common.js");
const fs = require("fs");

const out = path.join("runtime_output", "receiver");

const opt = {
  port: 5000,
  host: "0.0.0.0",
  key: null,
  once: false
};

for (const s of process.argv.slice(2)) {

  if (s.startsWith("--port=")) {
    opt.port = Number(s.slice(7));
  }

  else if (s.startsWith("--host=")) {
    opt.host = s.slice(7);
  }

  else if (s.startsWith("--key=")) {
    opt.key = s.slice(6);
  }

  else if (s === "--once") {
    opt.once = true;
  }
}

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


function processPackage(zipBytes) {

  const checks = {};


  // STAGE 1: ZIP validation
  let files;

  try {
    files = C.zipRead(zipBytes);
  } catch (e) {
    fail("zip", e.message);
  }

  const names = Object.keys(files).sort().join(",");

  if (names !== "manifest.json,share_1.enc,share_2.enc") {
    fail("zip", "Unexpected ZIP contents: " + names);
  }

  checks.zip = true;

  log(
    "  ZIP contents correct."
  );


  // STAGE 2: Manifest validation
  let mf;

  try {
    mf = JSON.parse(
      files["manifest.json"].toString("utf8")
    );
  } catch (e) {
    fail("manifest", "manifest.json is not valid JSON");
  }

  const okInt = (v) =>
    Number.isInteger(v) &&
    v > 0 &&
    v <= 20000;

  if (
    !mf ||
    mf.format !== "VCX-FLOW" ||
    mf.version !== 1
  ) {
    fail(
      "manifest",
      "Unsupported package format or version"
    );
  }

  if (
    !okInt(mf.width) ||
    !okInt(mf.height) ||
    mf.channels !== 3
  ) {
    fail(
      "manifest",
      "Invalid image dimensions"
    );
  }

  const rgbLen = mf.width * mf.height * 3;

  if (
    rgbLen > C.MAX_PACKAGE ||
    mf.original_size !== rgbLen
  ) {
    fail(
      "manifest",
      "Image size in manifest does not match dimensions"
    );
  }

  if (
    typeof mf.original_filename !== "string" ||
    mf.original_filename.length > 255
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
      "Invalid hex field in manifest"
    );
  }


  // NEW: Validate means of both shares
  if (
    !mf.share_means ||
    !Array.isArray(mf.share_means.share_1) ||
    !Array.isArray(mf.share_means.share_2) ||
    mf.share_means.share_1.length !== 3 ||
    mf.share_means.share_2.length !== 3
  ) {
    fail(
      "manifest",
      "Invalid RGB means for the two shares"
    );
  }

  for (const share of ["share_1", "share_2"]) {

    for (const value of mf.share_means[share]) {

      if (
        typeof value !== "string" ||
        !/^\d+(\.\d{4})$/.test(value) ||
        Number(value) < 0 ||
        Number(value) > 255
      ) {
        fail(
          "manifest",
          `Invalid RGB mean value in ${share}`
        );
      }

    }

  }


  if (
    !mf.selection ||
    typeof mf.selection !== "object"
  ) {
    fail(
      "manifest",
      "Invalid selection"
    );
  }

  if (
    files["share_1.enc"].length !== rgbLen + 16 ||
    files["share_2.enc"].length !== rgbLen + 16
  ) {
    fail(
      "manifest",
      "Encrypted share length is wrong"
    );
  }

  checks.manifest = true;

  log(
    `  Manifest valid: ${mf.width} x ${mf.height}`
  );


  // STAGE 3: Dynamic SHA-256 digest verification
  const digest = C.dynamicDigest(
    mf.share_means,
    mf.selection,
    mf.dynamic_nonce
  );

  if (digest !== mf.dynamic_digest) {

    fail(
      "digest",
      "Dynamic SHA-256 digest does not match the manifest"
    );
  }

  checks.digest = true;

  log(
    "  Dynamic SHA-256 digest verified:",
    digest
  );


  // STAGE 4: Master secret + HKDF
  const { master, where } = C.loadMaster(
    opt.key,
    false
  );

  const k = C.deriveKeys(
    master,
    Buffer.from(mf.hkdf_salt, "hex"),
    mf.dynamic_digest
  );

  log(
    `  Master secret loaded from ${where}; HKDF-SHA-256 keys derived.`
  );


  // STAGE 5: AES-256-GCM decryption
  let d1, d2;

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

  } catch (e) {

    fail(
      "aes-gcm",
      "Share 1 authentication tag invalid"
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

  } catch (e) {

    fail(
      "aes-gcm",
      "Share 2 authentication tag invalid"
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


  // Save decrypted shares
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


  // STAGE 6: Calculate RGB means of decrypted Share 1 and Share 2
  const receivedMeans1 = C.rgbMeans(d1);
  const receivedMeans2 = C.rgbMeans(d2);

  log("\n  DECRYPTED SHARE MEAN VERIFICATION");

  log("\n  SHARE 1");
  log(
    `  R=${receivedMeans1[0]} G=${receivedMeans1[1]} B=${receivedMeans1[2]}`
  );

  log("\n  SHARE 2");
  log(
    `  R=${receivedMeans2[0]} G=${receivedMeans2[1]} B=${receivedMeans2[2]}`
  );


  // Compare calculated means with sender's manifest
  const share1Match =
    receivedMeans1.join() ===
    mf.share_means.share_1.join();

  const share2Match =
    receivedMeans2.join() ===
    mf.share_means.share_2.join();

  if (!share1Match || !share2Match) {

    fail(
      "share-means",
      "RGB means of decrypted shares do not match the sender's manifest"
    );

  }

  checks.share_mean_verification = true;

  log(
    "  Share 1 RGB means: MATCH"
  );

  log(
    "  Share 2 RGB means: MATCH"
  );


  // STAGE 7: Reconstruct original image
  const rec = C.xorStack(
    new Uint8Array(d1),
    new Uint8Array(d2)
  );

  fs.writeFileSync(
    path.join(out, "reconstructed_image.png"),
    C.encodePng(
      rec,
      mf.width,
      mf.height
    )
  );


  // STAGE 8: Original image SHA-256 verification
  const recSha = C.sha256Hex(rec);
  const recMd5 = C.md5Hex(rec);

  if (recSha !== mf.original_sha256) {

    fail(
      "sha256",
      "SHA-256 of the rebuilt image differs from the original"
    );

  }

  checks.sha256 = true;

  log(
    "  SHA-256 of rebuilt image matches the original:",
    recSha
  );

  log(
    "  MD5 of rebuilt image:",
    recMd5,
    recMd5 === mf.original_md5 ? "(matches)" : "(DIFFERENT)"
  );


  // STAGE 9: Verification report
  const report = {

    status: "SUCCESS",

    checks,

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


// Send response to sender
const send = (sock, obj) =>
  new Promise((r) =>
    sock.write(
      C.lengthPrefix(
        Buffer.from(JSON.stringify(obj))
      ),
      r
    )
  );


fs.mkdirSync(out, { recursive: true });

try {
  C.loadMaster(opt.key, false);
} catch (e) {
  // Sender may create master.key later
}

let busy = false;

const server = net.createServer(async (sock) => {

  sock.setTimeout(60000, () => sock.destroy());

  sock.on("error", () => {});

  if (busy) {

    await send(sock, {
      status: "FAILURE",
      stage: "busy",
      message: "receiver is busy",
      checks: {}
    });

    sock.end();

    return;
  }

  busy = true;

  const reader = new C.Reader(sock);

  let reply;

  try {

    log(
      "\n" +
      "=".repeat(70) +
      "\nRECEIVER: connection from " +
      sock.remoteAddress
    );


    // STAGE 1: Read package length
    const len = Number(
      (await reader.take(8)).readBigUInt64BE()
    );

    if (!(len > 0 && len <= C.MAX_PACKAGE)) {

      fail(
        "length",
        "Invalid package length: " + len
      );

    }

    log(
      "STAGE 1  Package length:",
      len,
      "bytes"
    );


    // STAGE 2: Receive package
    const pkg = await reader.take(len);

    log(
      "STAGE 2  Package received completely."
    );


    // Process package
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


  try {
    await send(sock, reply);
  } catch (e) {
    // Sender disconnected
  }

  sock.end();

  busy = false;

  if (opt.once) {
    server.close();
  }

});


server.listen(
  opt.port,
  opt.host,
  () => {
    console.log(
      `RECEIVER listening on ${opt.host}:${opt.port} (press Ctrl+C to stop)`
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