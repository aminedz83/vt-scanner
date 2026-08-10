// api/check-hash.js — vérifie si un hash SHA-256 est déjà dans la base VT
// Appelé avant tout upload : si le fichier est connu, on retourne le résultat sans upload.
const { vtFetch, formatResult } = require("./_vt");

module.exports = async (req, res) => {
  if (req.method !== "GET") return res.status(405).json({ error: "Méthode non autorisée" });
  if (!process.env.VT_API_KEY) return res.status(500).json({ error: "VT_API_KEY manquante" });

  const { hash, filename, size } = req.query;
  if (!hash || hash.length !== 64) return res.status(400).json({ error: "Hash SHA-256 invalide" });

  try {
    const existing = await vtFetch(`/files/${hash}`);
    if (existing.status === 404) {
      return res.json({ found: false });
    }
    const data = await existing.json();
    return res.json({ found: true, ...formatResult(data, filename || "fichier", Number(size) || 0, hash, true) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
};