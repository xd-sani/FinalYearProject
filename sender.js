/*
 * sender.js - SENDER side of the secure image flow
 *
 * Run receiver first:
 *   node receiver.js
 *
 * Then:
 *   node sender.js photo.png
 *   node sender.js
 *
 * Options:
 *   --host=127.0.0.1
 *   --port=5000
 *   --max=1000
 *   --key=<64 hex>
 *   --no-send
 *
 * Attack demonstrations:
 *   --attack=flip
 *   --attack=manifest
 *   --attack=wrongkey
 *
 * Replay demonstration:
 *   node sender.js --resend
 */

"use strict";

const path = require("path");
const net = require("net");
const C = require("./common.js");

const { fs, crypto } = C;

// ============================================================================
// COMMAND-LINE ARGUMENTS
// ============================================================================

function parseArgs() {
  const a = {
    file: null,
    host: "127.0.0.1",
    port: 5000,
    max: 1000,
    key: null,
    attack: null,
    send: true,
    resend: false
  };

  for (const s of process.argv.slice(2)) {
    if (s.startsWith("--host=")) {
      a.host = s.slice(7);
    } else if (s.startsWith("--port=")) {
      a.port = Number(s.slice(7));
    } else if (s.startsWith("--max=")) {
      a.max = Number(s.slice(6));
    } else if (s.startsWith("--key=")) {
      a.key = s.slice(6);
    } else if (s.startsWith("--attack=")) {
      a.attack = s.slice(9);
    } else if (s === "--no-send") {
      a.send = false;
    } else if (s === "--resend") {
      a.resend = true;
    } else {
      a.file = s;
    }
  }

  if (
    a.attack &&
    !["flip", "manifest", "wrongkey"].includes(a.attack)
  ) {
    throw new Error(
      "--attack must be flip, manifest or wrongkey"
    );
  }

  if (
    !Number.isInteger(a.port) ||
    a.port < 1 ||
    a.port > 65535
  ) {
    throw new Error("Invalid --port");
  }

  if (
    !Number.isInteger(a.max) ||
    a.max < 0 ||
    a.max > 20000
  ) {
    throw new Error("--max must be 0 to 20000");
  }

  return a;
}

// ============================================================================
// TCP PACKAGE TRANSMISSION
// ============================================================================

function sendPackage(host, port, zip) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({
      host,
      port
    });

    let settled = false;

    const done = (err, value) => {
      if (settled) return;

      settled = true;

      if (err) reject(err);
      else resolve(value);
    };

    sock.setTimeout(60000, () => {
      sock.destroy();

      done(
        new Error(
          "receiver did not answer in 60 seconds"
        )
      );
    });

    sock.on("error", (e) => {
      done(
        new Error(
          `Cannot talk to receiver ${host}:${port} (${e.message}). Is node receiver.js running?`
        )
      );
    });

    sock.on("connect", async () => {
      const reader = new C.Reader(
        sock,
        1024 * 1024 + 8
      );

      try {
        sock.write(C.lengthPrefix(zip));

        const len = Number(
          (await reader.take(8)).readBigUInt64BE()
        );

        if (
          !Number.isSafeInteger(len) ||
          len < 2 ||
          len > 1024 * 1024
        ) {
          throw new Error(
            "receiver sent an invalid reply length"
          );
        }

        const reply = JSON.parse(
          (await reader.take(len)).toString("utf8")
        );

        done(null, reply);
      } catch (e) {
        done(e);
      } finally {
        sock.end();
      }
    });
  });
}

// ============================================================================
// MAIN SENDER PROCESS
// ============================================================================

async function main() {
  const opt = parseArgs();

  const out = path.join(
    "runtime_output",
    "sender"
  );

  const packagePath = path.join(
    out,
    "secure_image_package.zip"
  );

  console.log(
    "=".repeat(70) +
    "\nSENDER: SECURE IMAGE ENCRYPTION AND TRANSMISSION\n" +
    "=".repeat(70)
  );

  console.log(
    `STAGE 0  Hash/HMAC/HKDF self-test: ${C.selfTest()} test sizes passed.`
  );

  // --------------------------------------------------------------------------
  // REPLAY DEMONSTRATION
  // --------------------------------------------------------------------------

  if (opt.resend) {
    if (!fs.existsSync(packagePath)) {
      throw new Error(
        "No saved package found. Send an image successfully first."
      );
    }

    const oldPackage = fs.readFileSync(packagePath);

    console.log(
      "REPLAY DEMO  Resending the exact same saved package ID."
    );

    const reply = await sendPackage(
      opt.host,
      opt.port,
      oldPackage
    );

    console.log(
      "Receiver replied:",
      JSON.stringify(reply)
    );

    if (
      reply.status === "FAILURE" &&
      reply.stage === "replay"
    ) {
      console.log(
        "SUCCESS: receiver correctly rejected the previously accepted package."
      );

      return;
    }

    throw new Error(
      "Expected replay rejection, but receiver did not reject this package as a replay."
    );
  }

  // --------------------------------------------------------------------------
  // IMAGE INPUT
  // --------------------------------------------------------------------------

  fs.mkdirSync(
    path.join(out, "original_image"),
    { recursive: true }
  );

  let img;
  let name;

  if (opt.file) {
    if (!fs.existsSync(opt.file)) {
      throw new Error(
        "No image selected: file not found: " + opt.file
      );
    }

    name = path.basename(opt.file);

    fs.copyFileSync(
      opt.file,
      path.join(out, "original_image", name)
    );

    const raw = C.decodeImage(
      fs.readFileSync(opt.file),
      name
    );

    img = C.resize(
      raw.rgb,
      raw.W,
      raw.H,
      opt.max
    );

    console.log(
      `STAGE 1  Image selected: ${name} (${raw.W} x ${raw.H}) -> working size ${img.W} x ${img.H}.`
    );
  } else {
    name = "demo_picture.png";

    img = {
      rgb: C.demoPicture(200, 150),
      W: 200,
      H: 150
    };

    fs.writeFileSync(
      path.join(out, "original_image", name),
      C.encodePng(img.rgb, img.W, img.H)
    );

    console.log(
      "STAGE 1  Using built-in demo picture, 200 x 150."
    );
  }

  const { rgb, W, H } = img;

  // --------------------------------------------------------------------------
  // ORIGINAL IMAGE HASHES
  // --------------------------------------------------------------------------

  const origSha = C.sha256Hex(rgb);
  const origMd5 = C.md5Hex(rgb);

  console.log(
    `STAGE 2  RGB matrix: ${rgb.length} bytes.`
  );

  console.log(
    "         Original SHA-256:",
    origSha
  );

  console.log(
    "         Original MD5    :",
    origMd5,
    "(academic comparison only; not used for security)"
  );

  // --------------------------------------------------------------------------
  // XOR SECRET SHARING
  // --------------------------------------------------------------------------

  const { s1, s2 } = C.xorShares(
    rgb,
    W,
    H
  );

  fs.writeFileSync(
    path.join(out, "share_1.png"),
    C.encodePng(s1, W, H)
  );

  fs.writeFileSync(
    path.join(out, "share_2.png"),
    C.encodePng(s2, W, H)
  );

  console.log(
    "STAGE 3  Two XOR shares generated and saved."
  );

  // --------------------------------------------------------------------------
  // RGB MEAN CALCULATION OF SHARES
  // --------------------------------------------------------------------------

  const shareMeans = {
    share_1: C.rgbMeans(s1),
    share_2: C.rgbMeans(s2)
  };

  console.log(
    "\nSTAGE 4  RGB MEANS OF THE SHARES"
  );

  for (const key of ["share_1", "share_2"]) {
    console.log(
      `  ${key}: R=${shareMeans[key][0]} G=${shareMeans[key][1]} B=${shareMeans[key][2]}`
    );
  }

  // --------------------------------------------------------------------------
  // RANDOM SELECTION
  // --------------------------------------------------------------------------

  const selection = C.randomSelection();

  console.log(
    `\nSTAGE 5  Random channel order ${selection.order
      .map((i) => C.CHANNELS[i])
      .join("")}; picks [${selection.picks.join(", ")}].`
  );

  // --------------------------------------------------------------------------
  // DYNAMIC SHA-256
  // --------------------------------------------------------------------------

  const dynamicNonce = crypto
    .randomBytes(32)
    .toString("hex");

  const digest = C.dynamicDigest(
    shareMeans,
    selection,
    dynamicNonce
  );

  console.log(
    "STAGE 6  Dynamic nonce:",
    dynamicNonce
  );

  console.log(
    "         Dynamic SHA-256:",
    digest
  );

  // --------------------------------------------------------------------------
  // MASTER KEY
  // --------------------------------------------------------------------------

  const loaded = C.loadMaster(
    opt.key,
    true
  );

  if (loaded.created) {
    console.log(
      `STAGE 7  New 256-bit master secret created at ${loaded.where}.`
    );
  } else {
    console.log(
      `STAGE 7  Master secret loaded from ${loaded.where}.`
    );
  }

  let master = loaded.master;

  if (opt.attack === "wrongkey") {
    master = crypto.randomBytes(32);

    console.log(
      "         ATTACK DEMO: using an incorrect master secret."
    );
  }

  // --------------------------------------------------------------------------
  // HKDF KEY DERIVATION
  // --------------------------------------------------------------------------

  const salt = crypto.randomBytes(32);

  const k = C.deriveKeys(
    master,
    salt,
    digest
  );

  console.log(
    "         HKDF-SHA-256 derived independent share keys and nonces."
  );

  // --------------------------------------------------------------------------
  // AES-256-GCM ENCRYPTION
  // --------------------------------------------------------------------------

  let e1 = C.aesEncrypt(
    k.key1,
    k.nonce1,
    C.shareAad(name, W, H, 1),
    Buffer.from(s1)
  );

  let e2 = C.aesEncrypt(
    k.key2,
    k.nonce2,
    C.shareAad(name, W, H, 2),
    Buffer.from(s2)
  );

  console.log(
    `STAGE 8  AES-256-GCM encrypted shares: ${e1.length} and ${e2.length} bytes.`
  );

  if (opt.attack === "flip") {
    e2 = Buffer.from(e2);

    e2[Math.floor(e2.length / 2)] ^= 1;

    console.log(
      "         ATTACK DEMO: one ciphertext bit changed; GCM authentication must fail."
    );
  }

  // --------------------------------------------------------------------------
  // MANIFEST CREATION
  // --------------------------------------------------------------------------

  const manifest = {
    format: "VCX-FLOW",
    version: 2,

    package_id: crypto.randomBytes(16).toString("hex"),
    created_at: new Date().toISOString(),

    original_filename: name,

    width: W,
    height: H,
    channels: 3,

    original_size: rgb.length,

    original_sha256: origSha,
    original_md5: origMd5,

    share_means: shareMeans,

    selection,

    dynamic_nonce: dynamicNonce,
    dynamic_digest: digest,

    key_derivation: "HKDF-SHA-256",
    hkdf_salt: salt.toString("hex"),

    manifest_authentication: "HMAC-SHA-256",
    encryption: "AES-256-GCM",
    sharing: "XOR-2-out-of-2",

    share_size: e1.length
  };

  // --------------------------------------------------------------------------
  // MANIFEST AUTHENTICATION
  // --------------------------------------------------------------------------

  manifest.manifest_hmac = C.manifestMac(
    master,
    salt,
    manifest
  );

  if (opt.attack === "manifest") {
    manifest.share_means.share_1[0] = (
      Number(manifest.share_means.share_1[0]) + 1
    ).toFixed(4);

    console.log(
      "         ATTACK DEMO: manifest changed AFTER HMAC calculation; HMAC must fail."
    );
  }

  // --------------------------------------------------------------------------
  // ZIP PACKAGE CREATION
  // --------------------------------------------------------------------------

  const zip = C.zipWrite([
    {
      name: "manifest.json",
      data: Buffer.from(
        JSON.stringify(manifest, null, 2)
      )
    },
    {
      name: "share_1.enc",
      data: e1
    },
    {
      name: "share_2.enc",
      data: e2
    }
  ]);

  if (zip.length > C.MAX_PACKAGE) {
    throw new Error(
      "Package too large. Use --max=800 to shrink the picture."
    );
  }

  fs.writeFileSync(
    packagePath,
    zip
  );

  console.log(
    `STAGE 9  Authenticated ZIP package created: ${zip.length} bytes.`
  );

  console.log(
    "         Package ID:",
    manifest.package_id
  );

  if (!opt.send) {
    console.log(
      "         --no-send: stopped before TCP transmission."
    );

    return;
  }

  // --------------------------------------------------------------------------
  // TCP TRANSMISSION
  // --------------------------------------------------------------------------

  console.log(
    `STAGE 10 Sending to ${opt.host}:${opt.port}...`
  );

  const reply = await sendPackage(
    opt.host,
    opt.port,
    zip
  );

  console.log(
    "         Receiver replied:",
    JSON.stringify(reply)
  );

  // --------------------------------------------------------------------------
  // ATTACK TEST RESULT
  // --------------------------------------------------------------------------

  if (opt.attack) {
    if (reply.status === "FAILURE") {
      console.log(
        `ATTACK TEST PASSED: receiver rejected the ${opt.attack} attack at stage "${reply.stage}".`
      );

      return;
    }

    throw new Error(
      `Attack test FAILED: receiver accepted the ${opt.attack} attack.`
    );
  }

  // --------------------------------------------------------------------------
  // FINAL VERIFICATION
  // --------------------------------------------------------------------------

  const allOk =
    reply.status === "SUCCESS" &&
    reply.checks &&
    Object.values(reply.checks).every(
      (v) => v === true
    );

  if (!allOk) {
    throw new Error(
      "Receiver reported failure" +
      (reply.stage
        ? ` at stage "${reply.stage}"`
        : "") +
      ": " +
      (reply.message || "checks did not pass")
    );
  }

  console.log(
    "\nSTAGE 11 FINAL REPORT"
  );

  console.log(
    "  Original SHA-256 :",
    origSha
  );

  console.log(
    "  Receiver rebuilt :",
    reply.reconstructed_sha256
  );

  console.log(
    "  Checks           :",
    Object.entries(reply.checks)
      .map(
        ([n, v]) =>
          `${n}=${v ? "ok" : "FAIL"}`
      )
      .join("  ")
  );

  console.log(
    "\nSUCCESS: image reconstructed and all authenticity/integrity checks passed."
  );
}

// ============================================================================
// START
// ============================================================================

main().catch((e) => {
  console.error(
    "\nSENDER ERROR:",
    e.message
  );

  process.exit(1);
});