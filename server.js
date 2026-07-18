const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = "ignacior-boop";
const REPO_NAME = "altasrio";
const HIST_PATH = "data/historial.json";
const USERS_PATH = "data/usuarios.json";
const GITHUB_API = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${HIST_PATH}`;
const USERS_API = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${USERS_PATH}`;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || (() => {
  console.warn("SESSION_SECRET no configurado: se generó un secreto temporal. Las sesiones se invalidarán cada vez que el servidor se reinicie. Configurá SESSION_SECRET en Render para evitarlo.");
  return crypto.randomBytes(32).toString("hex");
})();

// --- Historial de análisis (persistido como un archivo JSON en el repo de GitHub,
// para que sea compartido entre todos los agentes y no se pierda con los reinicios/redeploys de Render) ---
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

// --- Usuarios (agentes) autenticados, también persistidos en el repo de GitHub ---
async function leerUsuariosDeGitHub() {
  const r = await fetch(USERS_API, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json"
    }
  });
  if (r.status === 404) return { usuarios: [], sha: undefined };
  if (!r.ok) throw new Error(`GitHub API ${r.status}: ${await r.text()}`);
  const data = await r.json();
  const content = Buffer.from(data.content, "base64").toString("utf-8");
  let usuarios = [];
  try { usuarios = JSON.parse(content); } catch { usuarios = []; }
  return { usuarios, sha: data.sha };
}

async function escribirUsuariosDeGitHub(usuarios, sha, mensaje) {
  const nuevoContenido = Buffer.from(JSON.stringify(usuarios, null, 2)).toString("base64");
  const putRes = await fetch(USERS_API, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ message: mensaje, content: nuevoContenido, sha })
  });
  if (!putRes.ok) throw new Error(`GitHub API ${putRes.status}: ${await putRes.text()}`);
}

function requireAuth(req, res, next) {
  const token = req.cookies?.rm_session;
  if (!token) return res.status(401).json({ error: "No autenticado" });
  try {
    req.user = jwt.verify(token, SESSION_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Sesión inválida o expirada" });
  }
}

function requireAdmin(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(500).json({ error: "ADMIN_PASSWORD no configurado en el servidor" });
  const pass = (req.body && req.body.adminPassword) || req.query.adminPassword;
  if (pass !== ADMIN_PASSWORD) return res.status(401).json({ error: "Contraseña de administrador incorrecta" });
  next();
}

app.post("/api/login", async (req, res) => {
  if (!GITHUB_TOKEN) return res.status(500).json({ error: "GITHUB_TOKEN no configurado en el servidor" });
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Usuario y contraseña requeridos" });
    const { usuarios } = await leerUsuariosDeGitHub();
    const u = usuarios.find(x => String(x.username).toLowerCase() === String(username).toLowerCase());
    if (!u || !bcrypt.compareSync(password, u.passwordHash)) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }
    const token = jwt.sign({ username: u.username, nombre: u.nombre }, SESSION_SECRET, { expiresIn: "30d" });
    res.cookie("rm_session", token, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ ok: true, nombre: u.nombre });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("rm_session");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const token = req.cookies?.rm_session;
  if (!token) return res.json({ nombre: null });
  try {
    const payload = jwt.verify(token, SESSION_SECRET);
    res.json({ nombre: payload.nombre });
  } catch {
    res.json({ nombre: null });
  }
});

// --- Administración de agentes (protegida por ADMIN_PASSWORD, independiente de las cuentas de agentes) ---
app.get("/api/admin/usuarios", requireAdmin, async (req, res) => {
  try {
    const { usuarios } = await leerUsuariosDeGitHub();
    res.json({ usuarios: usuarios.map(u => ({ username: u.username, nombre: u.nombre })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/usuarios", requireAdmin, async (req, res) => {
  try {
    const { username, password, nombre } = req.body || {};
    if (!username || !password || !nombre) return res.status(400).json({ error: "Usuario, contraseña y nombre son requeridos" });
    const { usuarios, sha } = await leerUsuariosDeGitHub();
    if (usuarios.some(u => String(u.username).toLowerCase() === String(username).toLowerCase())) {
      return res.status(400).json({ error: "Ese nombre de usuario ya existe" });
    }
    const passwordHash = bcrypt.hashSync(password, 10);
    const nuevo = [...usuarios, { username, passwordHash, nombre }];
    await escribirUsuariosDeGitHub(nuevo, sha, `Admin: alta de usuario ${username}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/usuarios/eliminar", requireAdmin, async (req, res) => {
  try {
    const { username } = req.body || {};
    const { usuarios, sha } = await leerUsuariosDeGitHub();
    const nuevo = usuarios.filter(u => String(u.username).toLowerCase() !== String(username).toLowerCase());
    await escribirUsuariosDeGitHub(nuevo, sha, `Admin: baja de usuario ${username}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/analizar", requireAuth, async (req, res) => {
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

app.get("/api/historial", requireAuth, async (req, res) => {
  if (!GITHUB_TOKEN) return res.json({ items: [] });
  try {
    const { items } = await leerHistorialDeGitHub();
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/historial", requireAuth, async (req, res) => {
  if (!GITHUB_TOKEN) {
    return res.status(500).json({ error: "GITHUB_TOKEN no configurado en el servidor" });
  }
  try {
    const { items, sha } = await leerHistorialDeGitHub();
    const entry = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      fecha: new Date().toISOString(),
      agente: req.body.agente || null,
      cargado_por: req.user.nombre || null,
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
