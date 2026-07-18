const express = require("express");
const path = require("path");

const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/analizar", async (req, res) => {
  const API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!API_KEY) {
    return res.status(500).json({ error: "API key no configurada en el servidor" });
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Historial de análisis (persistido como un archivo JSON en el repo de GitHub,
// para que sea compartido entre todos los agentes y no se pierda con los reinicios/redeploys de Render) ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = "ignacior-boop";
const REPO_NAME = "altasrio";
const HIST_PATH = "data/historial.json";
const GITHUB_API = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${HIST_PATH}`;

async function leerHistorialDeGitHub() {
  const r = await fetch(GITHUB_API, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json"
    }
  });
  if (r.status === 404) return { items: [], sha: undefined };
  if (!r.ok) throw new Error(`GitHub API ${r.status}: ${await r.text()}`);
  const data = await r.json();
  const content = Buffer.from(data.content, "base64").toString("utf-8");
  let items = [];
  try { items = JSON.parse(content); } catch { items = []; }
  return { items, sha: data.sha };
}

app.get("/api/historial", async (req, res) => {
  if (!GITHUB_TOKEN) return res.json({ items: [] });
  try {
    const { items } = await leerHistorialDeGitHub();
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/historial", async (req, res) => {
  if (!GITHUB_TOKEN) {
    return res.status(500).json({ error: "GITHUB_TOKEN no configurado en el servidor" });
  }
  try {
    const { items, sha } = await leerHistorialDeGitHub();
    const entry = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      fecha: new Date().toISOString(),
      agente: req.body.agente || null,
      direccion: req.body.direccion || null,
      veredicto: req.body.veredicto || null,
      resultado: req.body.resultado || null
    };
    const nuevoItems = [entry, ...items].slice(0, 300);
    const nuevoContenido = Buffer.from(JSON.stringify(nuevoItems, null, 2)).toString("base64");

    const putRes = await fetch(GITHUB_API, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: `Historial: analisis de ${entry.direccion || "propiedad"} (${entry.veredicto || "?"})`,
        content: nuevoContenido,
        sha
      })
    });
    if (!putRes.ok) throw new Error(`GitHub API ${putRes.status}: ${await putRes.text()}`);

    res.json({ ok: true, entry });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
