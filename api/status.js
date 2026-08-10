// api/status.js — le front appelle GET /api/status?id=...&hash=...&filename=...&size=...
// toutes les quelques secondes, jusqu'à recevoir done:true.
const { vtFetch, formatResult } = require("./_vt");

module.exports = async (req, res) => {
  if (req.method !== "GET") return res.status(405).json({ error: "Méthode non autorisée" });
  if (!process.env.VT_API_KEY) return res.status(500).json({ error: "VT_API_KEY manquante côté serveur" });

  const { id, hash, filename, size } = req.query;
  if (!id || !hash) return res.status(400).json({ error: "Paramètres manquants" });

  try {
    const analysisRes = await vtFetch(`/analyses/${id}`);
    const analysisData = await analysisRes.json();

    if (analysisData.data.attributes.status !== "completed") {
      return res.json({ done: false });
    }

    const fileRes = await vtFetch(`/files/${hash}`);
    const fileData = await fileRes.json();
    return res.json(formatResult(fileData, filename, Number(size), hash, false));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
};
