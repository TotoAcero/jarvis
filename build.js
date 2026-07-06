// Build de Jarvis: toma ../dashboard-data.js + jarvis-config.json (PIN, no se commitea),
// cifra los datos (PBKDF2 + AES-256-GCM, compatible con WebCrypto) y escribe data.enc.js.
// Uso: node build.js   (desde la carpeta jarvis/)
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const dir = __dirname;
const config = JSON.parse(fs.readFileSync(path.join(dir, "jarvis-config.json"), "utf8"));
if (!config.pin || String(config.pin).length < 4) throw new Error("PIN inválido en jarvis-config.json");

// Cargar datos
const src = fs.readFileSync(path.join(dir, "..", "dashboard-data.js"), "utf8");
const sandbox = { window: {} };
new Function("window", src)(sandbox.window);
const data = sandbox.window.TOBIAS_DATA;
if (!data) throw new Error("dashboard-data.js no expone TOBIAS_DATA");

// Inyectar config publicable (no sensible)
data.config = data.config || {};
if (config.inboxUrl) data.config.inboxUrl = config.inboxUrl;

// Cifrar
const ITER = 200000;
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(String(config.pin), salt, ITER, 32, "sha256");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const pt = Buffer.from(JSON.stringify(data), "utf8");
const ct = Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]); // ct||tag = formato WebCrypto

const blob = {
  v: 1,
  iter: ITER,
  salt: salt.toString("base64"),
  iv: iv.toString("base64"),
  ct: ct.toString("base64"),
  gen: data.generado || new Date().toISOString().slice(0, 10)
};
fs.writeFileSync(path.join(dir, "data.enc.js"), "window.JARVIS_BLOB = " + JSON.stringify(blob) + ";\n");

// Verificación: descifrar de vuelta
const vKey = crypto.pbkdf2Sync(String(config.pin), salt, ITER, 32, "sha256");
const vDec = crypto.createDecipheriv("aes-256-gcm", vKey, iv);
vDec.setAuthTag(ct.subarray(ct.length - 16));
const vPt = Buffer.concat([vDec.update(ct.subarray(0, ct.length - 16)), vDec.final()]).toString("utf8");
const roundtrip = JSON.parse(vPt);
if (roundtrip.generado !== data.generado) throw new Error("Roundtrip de cifrado falló");
console.log("✔ data.enc.js generado y verificado (" + ct.length + " bytes, datos del " + blob.gen + ")");
