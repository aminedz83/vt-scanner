// api/_vt.js — utilitaires partagés entre scan.js et status.js
const VT_API_KEY = process.env.VT_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

async function vtFetch(path, options = {}) {
  const res = await fetch(`${VT_BASE}${path}`, {
    ...options,
    headers: { "x-apikey": VT_API_KEY, ...(options.headers || {}) },
  });
  if (res.status === 429) {
    const err = new Error("Limite VirusTotal atteinte (4 requêtes/minute). Patiente environ 1 minute.");
    err.rateLimited = true;
    throw err;
  }
  if (!res.ok && res.status !== 404) {
    const text = await res.text();
    throw new Error(`VirusTotal ${res.status}: ${text}`);
  }
  return res;
}

function formatResult(vtData, filename, size, hash, cached) {
  const stats = vtData.data.attributes.last_analysis_stats;
  const results = vtData.data.attributes.last_analysis_results;
  const engines = Object.entries(results).map(([engine, r]) => ({
    engine,
    category: r.category,
    result: r.result,
  }));
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);

  return {
    done: true,
    filename,
    size,
    hash,
    cached,
    scanDate: new Date(vtData.data.attributes.last_analysis_date * 1000).toISOString(),
    stats: { malicious, suspicious, harmless: stats.harmless || 0, undetected: stats.undetected || 0, total },
    permalink: `https://www.virustotal.com/gui/file/${hash}`,
    engines,
  };
}

module.exports = { VT_API_KEY, vtFetch, formatResult };