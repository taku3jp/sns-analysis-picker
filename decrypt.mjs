// 管理者用: webhook.site に届いた暗号化回答を取得・復号する
// 使い方: node decrypt.mjs [--json]
// 秘密鍵: admin/admin-private.pem（このファイルは公開しない）

import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const { subtle } = webcrypto;
const TOKEN_ID = "0196fd60-419f-4e2c-bc0c-fdca16cecb47";
const HERE = dirname(fileURLToPath(import.meta.url));
const KEY_PATH = join(HERE, "admin", "admin-private.pem");
const OUT_JSON = join(HERE, "admin", "responses.json");

const pem = readFileSync(KEY_PATH, "utf8");
const der = Buffer.from(
  pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, ""),
  "base64"
);
const privKey = await subtle.importKey(
  "pkcs8",
  der,
  { name: "RSA-OAEP", hash: "SHA-256" },
  false,
  ["decrypt"]
);

const asJson = process.argv.includes("--json");
const results = [];
let page = 1;
let total = 0;

while (true) {
  const res = await fetch(
    `https://webhook.site/token/${TOKEN_ID}/requests?per_page=100&page=${page}&sorting=newest`
  );
  if (!res.ok) throw new Error(`list API failed: ${res.status}`);
  const body = await res.json();
  for (const r of body.data || []) {
    total++;
    let content = r.content || "";
    let blob;
    try {
      blob = JSON.parse(Buffer.from(content, "base64").toString("utf8"));
    } catch {
      console.error(`[skip] ${r.created_at} base64/JSON parse失敗（テスト投稿等）`);
      continue;
    }
    if (!blob || blob.v !== 1) {
      console.error(`[skip] ${r.created_at} 未知の形式`);
      continue;
    }
    try {
      const rawAes = await subtle.decrypt(
        { name: "RSA-OAEP" },
        privKey,
        Buffer.from(blob.k, "base64")
      );
      const aes = await subtle.importKey("raw", rawAes, "AES-GCM", false, ["decrypt"]);
      const pt = await subtle.decrypt(
        { name: "AES-GCM", iv: Buffer.from(blob.i, "base64") },
        aes,
        Buffer.from(blob.d, "base64")
      );
      results.push({
        received_at: r.created_at,
        ip: r.ip,
        text: new TextDecoder().decode(pt),
      });
    } catch (e) {
      console.error(`[skip] ${r.created_at} 復号失敗: ${e.message}`);
    }
  }
  if (body.is_last_page) break;
  page++;
}

if (asJson) {
  writeFileSync(OUT_JSON, JSON.stringify(results, null, 2));
  console.error(`${results.length}/${total}件を復号して ${OUT_JSON} に保存`);
} else {
  console.log(`受信 ${total}件 / 復号成功 ${results.length}件`);
  for (const r of results) {
    console.log("\n=================================");
    console.log(`受信: ${r.received_at}`);
    console.log("---------------------------------");
    console.log(r.text);
  }
}
