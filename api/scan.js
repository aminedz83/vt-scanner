// api/scan.js — reçoit le fichier en base64 (JSON), l'envoie à VirusTotal
const crypto = require("crypto");
const { vtFetch, formatResult } = require("./_vt");

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// Lit le corps JSON manuellement (bodyParser désactivé)
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => { data += chunk; });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });
  if (!process.env.VT_API_KEY) return res.status(500).json({ error: "VT_API_KEY manquante côté serveur" });

  try {
    const raw = await readBody(req);
    let body;
    try { body = JSON.parse(raw); }
    catch { return res.status(400).json({ error: "JSON invalide" }); }

    const { fileBase64, filename } = body;
    if (!fileBase64) return res.status(400).json({ error: "Aucun fichier reçu" });

    const buffer = Buffer.from(fileBase64, "base64");
    const name = filename || "fichier";
    const size = buffer.length;
    const hash = sha256(buffer);

    // Déjà connu de VirusTotal ?
    const existing = await vtFetch(`/files/${hash}`);
    if (existing.status === 200) {
      const data = await existing.json();
      return res.json(formatResult(data, name, size, hash, true));
    }

    // Sinon on l'envoie pour analyse
    const vtForm = new FormData();
    vtForm.append("file", new Blob([buffer]), name);
    const uploadRes = await vtFetch("/files", { method: "POST", body: vtForm });
    const uploadData = await uploadRes.json();

    if (!uploadData.data || !uploadData.data.id) {
      return res.status(502).json({ error: "Réponse VirusTotal inattendue" });
    }

    return res.json({ done: false, analysisId: uploadData.data.id, hash, filename: name, size });
  } catch (err) {
    console.error("scan error:", err);
    return res.status(500).json({ error: err.message || "Erreur inconnue" });
  }
}

module.exports = handler;
module.exports.config = { api: { bodyParser: false } };