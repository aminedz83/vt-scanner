// api/health.js — route légère pour "réveiller" la connexion avant les vrais scans
module.exports = (req, res) => {
  res.json({ ok: true, time: Date.now() });
};