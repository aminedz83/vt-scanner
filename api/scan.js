// api/scan.js — reçoit le fichier en base64 (JSON), l'envoie à VirusTotal
const crypto = require("crypto");
const { vtFetch, formatResult } = require("./_vt");

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// Lit le corps de la requête en brut (indépendant du bodyParser Vercel)
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });
  if (!process.env.VT_API_KEY) return res.status(500).json({ error: "VT_API_KEY manquante côté serveur" });

  try {
    // req.body peut déjà être parsé par Vercel, sinon on lit le flux brut
    let body = req.body;
    if (!body || typeof body === "string") {
      const raw = typeof body === "string" ? body : await readRawBody(req);
      try { body = JSON.parse(raw); }
      catch { return res.status(400).json({ error: "JSON invalide" }); }
    }

    const { fileBase64, filename } = body || {};
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
    if (err.rateLimited) return res.status(429).json({ error: err.message });
    return res.status(500).json({ error: err.message || "Erreur inconnue" });
  }
};