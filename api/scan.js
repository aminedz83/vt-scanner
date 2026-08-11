// api/scan.js — reçoit le fichier, l'envoie à VirusTotal, répond tout de suite
const crypto = require("crypto");
const fs = require("fs");
const { formidable } = require("formidable");
const { vtFetch, formatResult } = require("./_vt");

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });
  if (!process.env.VT_API_KEY) return res.status(500).json({ error: "VT_API_KEY manquante côté serveur" });

  try {
    const form = formidable({ maxFileSize: 32 * 1024 * 1024, keepExtensions: true });

    const files = await new Promise((resolve, reject) => {
      form.parse(req, (err, fields, files) => {
        if (err) reject(err);
        else resolve(files);
      });
    });

    let uploaded = files.file;
    if (Array.isArray(uploaded)) uploaded = uploaded[0];
    if (!uploaded) return res.status(400).json({ error: "Aucun fichier reçu" });

    const buffer = fs.readFileSync(uploaded.filepath);
    const filename = uploaded.originalFilename || "fichier";
    const size = uploaded.size || buffer.length;
    const hash = sha256(buffer);

    const existing = await vtFetch(`/files/${hash}`);
    if (existing.status === 200) {
      const data = await existing.json();
      return res.json(formatResult(data, filename, size, hash, true));
    }

    const vtForm = new FormData();
    vtForm.append("file", new Blob([buffer]), filename);
    const uploadRes = await vtFetch("/files", { method: "POST", body: vtForm });
    const uploadData = await uploadRes.json();

    if (!uploadData.data || !uploadData.data.id) {
      return res.status(502).json({ error: "Réponse VirusTotal inattendue à l'upload" });
    }

    return res.json({
      done: false,
      analysisId: uploadData.data.id,
      hash,
      filename,
      size,
    });
  } catch (err) {
    console.error("scan error:", err);
    return res.status(500).json({ error: err.message || "Erreur inconnue" });
  }
}

module.exports = handler;
module.exports.config = { api: { bodyParser: false } };