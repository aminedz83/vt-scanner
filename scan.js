// api/scan.js — reçoit le fichier, l'envoie à VirusTotal, répond tout de suite
// (ne bloque pas jusqu'à la fin de l'analyse : voir status.js pour le polling).
const crypto = require("crypto");
const formidable = require("formidable");
const { vtFetch, formatResult } = require("./_vt");

module.exports.config = { api: { bodyParser: false } };

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });
  if (!process.env.VT_API_KEY) return res.status(500).json({ error: "VT_API_KEY manquante côté serveur" });

  try {
    const form = formidable({ maxFileSize: 32 * 1024 * 1024 });
    const [, files] = await form.parse(req);
    const uploaded = files.file?.[0];
    if (!uploaded) return res.status(400).json({ error: "Aucun fichier reçu" });

    const fs = require("fs");
    const buffer = fs.readFileSync(uploaded.filepath);
    const filename = uploaded.originalFilename || "fichier";
    const size = uploaded.size;
    const hash = sha256(buffer);

    // Déjà connu de VirusTotal ?
    const existing = await vtFetch(`/files/${hash}`);
    if (existing.status === 200) {
      const data = await existing.json();
      return res.json(formatResult(data, filename, size, hash, true));
    }

    // Sinon on l'envoie pour analyse
    const vtForm = new FormData();
    vtForm.append("file", new Blob([buffer]), filename);
    const uploadRes = await vtFetch("/files", { method: "POST", body: vtForm });
    const uploadData = await uploadRes.json();

    return res.json({
      done: false,
      analysisId: uploadData.data.id,
      hash,
      filename,
      size,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
};
