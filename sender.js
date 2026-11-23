/*
 * sender.js - SENDER side of the flowchart
 *
 * Run (receiver must already be running):
 *   node sender.js
 *   node sender.js photo.png
 *
 * Extra options:
 *   --host=127.0.0.1
 *   --port=5000
 *   --key=<64 hex>
 *   --no-send
 *
 * Attack demos:
 *   --attack=flip
 *   --attack=manifest
 *   --attack=wrongkey
 */
"use strict";

const path = require("path");
const net = require("net");
const C = require("./common.js");
const { fs, crypto } = C;

function parseArgs() {
  const a = {
    file: null,
    host: "127.0.0.1",
    port: 5000,
    max: 1000,
    key: null,
    attack: null,
    send: true
  };

  for (const s of process.argv.slice(2)) {
    if (s.startsWith("--host=")) a.host = s.slice(7);
    else if (s.startsWith("--port=")) a.port = Number(s.slice(7));
    else if (s.startsWith("--max=")) a.max = Number(s.slice(6));
    else if (s.startsWith("--key=")) a.key = s.slice(6);
    else if (s.startsWith("--attack=")) a.attack = s.slice(9);
    else if (s === "--no-send") a.send = false;
    else a.file = s;
  }

  if (a.attack && !["flip", "manifest", "wrongkey"].includes(a.attack)) {
    throw new Error("--attack must be flip, manifest or wrongkey");
  }

  return a;
}

// STAGE 10: TCP transmission
function sendPackage(host, port, zip) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port }, async () => {
      try {
        const reader = new C.Reader(sock);

        sock.write(C.lengthPrefix(zip));

        const len = Number(
          (await reader.take(8)).readBigUInt64BE()
        );

        if (len < 2 || len > 1024 * 1024) {
          throw new Error("receiver sent an invalid reply length");
        }

        resolve(
          JSON.parse((await reader.take(len)).toString("utf8"))
        );

      } catch (e) {
        reject(e);
      } finally {
        sock.end();
      }
    });

    sock.setTimeout(60000, () => {
      sock.destroy();
      reject(new Error("receiver did not answer in 60 seconds"));
    });

    sock.on("error", (e) => {
      reject(
        new Error(
          `Cannot talk to receiver ${host}:${port} (${e.message}). Is "node receiver.js" running?`
        )
      );
    });
  });
}

async function main() {

  const opt = parseArgs();

  console.log(
    "=".repeat(70) +
    "\nSENDER: SECURE IMAGE ENCRYPTION AND TRANSMISSION\n" +
    "=".repeat(70)
  );

  // STAGE 0: Hash self-test
  console.log(
    `STAGE 0  Hash code check: MD5, SHA-256, HMAC, HKDF (${C.selfTest()} test sizes).`
  );

  // STAGE 1: Select image
  const out = path.join("runtime_output", "sender");

  fs.mkdirSync(
    path.join(out, "original_image"),
    { recursive: true }
  );

  let img, name;

  if (opt.file) {

    if (!fs.existsSync(opt.file)) {
      throw new Error("No image selected: file not found: " + opt.file);
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

  // STAGE 2: Original image SHA-256 and MD5
  const origSha = C.sha256Hex(rgb);
  const origMd5 = C.md5Hex(rgb);

  console.log(
    `STAGE 2  RGB matrices read: ${rgb.length} bytes.`
  );

  console.log("         Original SHA-256:", origSha);
  console.log("         Original MD5    :", origMd5);


  // STAGE 3: XOR secret sharing
  const { s1, s2 } = C.xorShares(rgb, W, H);

  fs.writeFileSync(
    path.join(out, "share_1.png"),
    C.encodePng(s1, W, H)
  );

  fs.writeFileSync(
    path.join(out, "share_2.png"),
    C.encodePng(s2, W, H)
  );

  console.log(
    "STAGE 3  XOR shares generated and saved."
  );


  // STAGE 4: Calculate RGB means of BOTH shares
  const means1 = C.rgbMeans(s1);
  const means2 = C.rgbMeans(s2);

  const shareMeans = {
    share_1: means1,
    share_2: means2
  };

  console.log("\nSTAGE 4  RGB MEAN CALCULATION");

  console.log("\n  SHARE 1");
  console.log(`  R Mean: ${means1[0]}`);
  console.log(`  G Mean: ${means1[1]}`);
  console.log(`  B Mean: ${means1[2]}`);

  console.log("\n  SHARE 2");
  console.log(`  R Mean: ${means2[0]}`);
  console.log(`  G Mean: ${means2[1]}`);
  console.log(`  B Mean: ${means2[2]}`);


  // STAGE 5: Random selection
  const selection = C.randomSelection();

  console.log(
    `\nSTAGE 5  Random selection: channel order ${selection.order.map((i) => C.CHANNELS[i]).join("")}, picks [${selection.picks.join(", ")}]`
  );


  // STAGE 6: Dynamic SHA-256 digest
  const dynNonce = crypto.randomBytes(32).toString("hex");

  const digest = C.dynamicDigest(
    shareMeans,
    selection,
    dynNonce
  );

  console.log(
    "STAGE 6  Dynamic nonce:", dynNonce
  );

  console.log(
    "         Dynamic SHA-256 digest:", digest
  );


  // STAGE 7: Master secret and HKDF
  const m = C.loadMaster(opt.key, true);

  if (m.created) {
    console.log(
      `STAGE 7  New master secret created -> ${m.where}`
    );
  } else {
    console.log(
      `STAGE 7  Master secret loaded from ${m.where}.`
    );
  }

  let master = m.master;

  if (opt.attack === "wrongkey") {
    master = crypto.randomBytes(32);

    console.log(
      "         ATTACK DEMO: using a different master secret."
    );
  }

  const salt = crypto.randomBytes(32);

  const k = C.deriveKeys(
    master,
    salt,
    digest
  );

  console.log(
    "         HKDF-SHA-256 keys derived."
  );


  // STAGE 8: AES-256-GCM encryption
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
    `STAGE 8  AES-256-GCM: Share 1 ${s1.length} -> ${e1.length} bytes, Share 2 ${s2.length} -> ${e2.length} bytes.`
  );

  if (opt.attack === "flip") {

    e2 = Buffer.from(e2);

    e2[e2.length >> 1] ^= 1;

    console.log(
      "         ATTACK DEMO: one bit of share_2.enc changed."
    );
  }


  // STAGE 9: Manifest + ZIP package
  const manifest = {

    format: "VCX-FLOW",
    version: 1,

    original_filename: name,

    width: W,
    height: H,
    channels: 3,

    original_size: rgb.length,

    original_sha256: origSha,
    original_md5: origMd5,

    // NEW: means of both shares
    share_means: shareMeans,

    selection,

    dynamic_nonce: dynNonce,
    dynamic_digest: digest,

    key_derivation: "HKDF-SHA-256",
    hkdf_salt: salt.toString("hex"),

    encryption: "AES-256-GCM",
    sharing: "XOR-2-out-of-2",

    share_size: e1.length
  };


  // Manifest attack demonstration
  if (opt.attack === "manifest") {

    manifest.share_means.share_1[0] =
      (Number(manifest.share_means.share_1[0]) + 1).toFixed(4);

    console.log(
      "         ATTACK DEMO: Share 1 red mean changed in manifest."
    );
  }


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
    path.join(out, "secure_image_package.zip"),
    zip
  );

  console.log(
    `STAGE 9  Secure package created: ${zip.length} bytes.`
  );

  if (!opt.send) {
    console.log(
      "         --no-send: stopped before TCP."
    );
    return;
  }


  // STAGE 10: TCP transmission
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

  const allOk =
    reply.status === "SUCCESS" &&
    reply.checks &&
    Object.values(reply.checks).every((v) => v === true);

  if (!allOk) {

    throw new Error(
      "Receiver reported failure" +
      (reply.stage ? ` at "${reply.stage}"` : "") +
      ": " +
      (reply.message || "checks did not pass")
    );
  }


  // STAGE 11: Final report
  console.log("\nSTAGE 11 FINAL REPORT");

  console.log("  Original SHA-256 :", origSha);

  console.log(
    "  Receiver rebuilt :",
    reply.reconstructed_sha256
  );

  console.log(
    "  Checks           :",
    Object.entries(reply.checks)
      .map(([n, v]) => `${n}=${v ? "ok" : "FAIL"}`)
      .join("  ")
  );

  console.log(
    "\nSUCCESS: the image reached the receiver unchanged."
  );
}

main().catch((e) => {
  console.error("\nSENDER ERROR:", e.message);
  process.exit(1);
});