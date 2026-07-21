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

const ROLES_VALIDOS = ["propietario", "administrador", "staff"];

// Ventana deslizante de inactividad: la sesión se renueva en cada request autenticado
// y expira sola si pasan más de 40 minutos sin actividad. La cookie no lleva maxAge
// (cookie de sesión), por lo que además se pierde al cerrar el navegador.
const SESSION_MAX_IDLE = "40m";

function firmarSesion(payload) {
  return jwt.sign({ username: payload.username, nombre: payload.nombre, rol: payload.rol }, SESSION_SECRET, { expiresIn: SESSION_MAX_IDLE });
}

function setSessionCookie(res, token) {
  res.cookie("rm_session", token, { httpOnly: true, sameSite: "lax", secure: true });
}

// --- Historial de análisis (persistido como un archivo JSON en el repo de GitHub,
// para que sea compartido entre todos los usuarios y no se pierda con los reinicios/redeploys de Render) ---
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

// --- Usuarios autenticados, también persistidos en el repo de GitHub ---
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

// Un usuario con rol "administrador" puede gestionar a cualquiera excepto a los "propietario".
// Un "propietario" puede gestionar a cualquiera, incluido a sí mismo y a otros propietarios.
function puedeGestionar(actorRol, targetRol) {
  if (actorRol === "propietario") return true;
  if (actorRol === "administrador") return (targetRol || "staff") !== "propietario";
  return false;
}

function requireAuth(req, res, next) {
  const token = req.cookies?.rm_session;
  if (!token) return res.status(401).json({ error: "No autenticado" });
  try {
    const payload = jwt.verify(token, SESSION_SECRET);
    req.user = payload;
    // Actividad detectada: renovamos la ventana de 40 minutos
    setSessionCookie(res, firmarSesion(payload));
    next();
  } catch (e) {
    res.clearCookie("rm_session");
    res.status(401).json({ error: "Sesión inválida o expirada" });
  }
}

function requireGestion(req, res, next) {
  const rol = req.user && req.user.rol;
  if (rol !== "propietario" && rol !== "administrador") {
    return res.status(403).json({ error: "No tenés permisos para gestionar usuarios" });
  }
  next();
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
    const rol = ROLES_VALIDOS.includes(u.rol) ? u.rol : "staff";
    setSessionCookie(res, firmarSesion({ username: u.username, nombre: u.nombre, rol }));
    res.json({ ok: true, nombre: u.nombre, rol });
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
    setSessionCookie(res, firmarSesion(payload));
    res.json({ nombre: payload.nombre, rol: payload.rol || "staff", username: payload.username });
  } catch {
    res.clearCookie("rm_session");
    res.json({ nombre: null });
  }
});

// --- Gestión de usuarios dentro de la app, para sesiones con rol Propietario/Administrador ---
app.get("/api/usuarios", requireAuth, requireGestion, async (req, res) => {
  try {
    const { usuarios } = await leerUsuariosDeGitHub();
    res.json({
      usuarios: usuarios.map(u => ({ username: u.username, nombre: u.nombre, rol: ROLES_VALIDOS.includes(u.rol) ? u.rol : "staff" }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/usuarios", requireAuth, requireGestion, async (req, res) => {
  try {
    const { username, password, nombre, rol } = req.body || {};
    if (!username || !password || !nombre || !rol) return res.status(400).json({ error: "Todos los campos son requeridos" });
    if (!ROLES_VALIDOS.includes(rol)) return res.status(400).json({ error: "Rol inválido" });
    if (req.user.rol === "administrador" && rol === "propietario") {
      return res.status(403).json({ error: "No podés crear usuarios con rol Propietario" });
    }
    const { usuarios, sha } = await leerUsuariosDeGitHub();
    if (usuarios.some(u => String(u.username).toLowerCase() === String(username).toLowerCase())) {
      return res.status(400).json({ error: "Ese nombre de usuario ya existe" });
    }
    const passwordHash = bcrypt.hashSync(password, 10);
    const nuevo = [...usuarios, { username, passwordHash, nombre, rol }];
    await escribirUsuariosDeGitHub(nuevo, sha, `Usuarios: alta de ${username} (${rol})`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/usuarios/reset-password", requireAuth, requireGestion, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password || password.length < 4) return res.status(400).json({ error: "Contraseña inválida (mínimo 4 caracteres)" });
    const { usuarios, sha } = await leerUsuariosDeGitHub();
    const idx = usuarios.findIndex(u => String(u.username).toLowerCase() === String(username).toLowerCase());
    if (idx === -1) return res.status(404).json({ error: "Usuario no encontrado" });
    const target = usuarios[idx];
    if (String(target.username).toLowerCase() === String(req.user.username).toLowerCase()) {
      return res.status(400).json({ error: "No podés restablecer tu propia contraseña desde acá" });
    }
    if (!puedeGestionar(req.user.rol, target.rol)) {
      return res.status(403).json({ error: "No tenés permisos para modificar este usuario" });
    }
    usuarios[idx] = { ...target, passwordHash: bcrypt.hashSync(password, 10) };
    await escribirUsuariosDeGitHub(usuarios, sha, `Usuarios: reset de contraseña de ${username}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/usuarios/eliminar", requireAuth, requireGestion, async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: "Usuario requerido" });
    if (String(username).toLowerCase() === String(req.user.username).toLowerCase()) {
      return res.status(400).json({ error: "No podés eliminar tu propia cuenta" });
    }
    const { usuarios, sha } = await leerUsuariosDeGitHub();
    const target = usuarios.find(u => String(u.username).toLowerCase() === String(username).toLowerCase());
    if (!target) return res.status(404).json({ error: "Usuario no encontrado" });
    if (!puedeGestionar(req.user.rol, target.rol)) {
      return res.status(403).json({ error: "No tenés permisos para eliminar este usuario" });
    }
    const nuevo = usuarios.filter(u => String(u.username).toLowerCase() !== String(username).toLowerCase());
    await escribirUsuariosDeGitHub(nuevo, sha, `Usuarios: baja de ${username}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Administración de usuarios vía ?admin=1, protegida por ADMIN_PASSWORD (independiente de las cuentas
// de usuario; sirve como acceso de arranque/recuperación cuando todavía no existe ningún Propietario) ---
app.get("/api/admin/usuarios", requireAdmin, async (req, res) => {
  try {
    const { usuarios } = await leerUsuariosDeGitHub();
    res.json({ usuarios: usuarios.map(u => ({ username: u.username, nombre: u.nombre, rol: ROLES_VALIDOS.includes(u.rol) ? u.rol : "staff" })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/usuarios", requireAdmin, async (req, res) => {
  try {
    const { username, password, nombre, rol } = req.body || {};
    if (!username || !password || !nombre) return res.status(400).json({ error: "Usuario, contraseña y nombre son requeridos" });
    const rolFinal = ROLES_VALIDOS.includes(rol) ? rol : "staff";
    const { usuarios, sha } = await leerUsuariosDeGitHub();
    if (usuarios.some(u => String(u.username).toLowerCase() === String(username).toLowerCase())) {
      return res.status(400).json({ error: "Ese nombre de usuario ya existe" });
    }
    const passwordHash = bcrypt.hashSync(password, 10);
    const nuevo = [...usuarios, { username, passwordHash, nombre, rol: rolFinal }];
    await escribirUsuariosDeGitHub(nuevo, sha, `Admin: alta de usuario ${username} (${rolFinal})`);
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

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Tipos de error de la API de Anthropic que son transitorios (el servidor de
// Anthropic está saturado o hubo un problema momentáneo de su lado) y por lo
// tanto vale la pena reintentar automáticamente antes de mostrarle un error
// al usuario. "overloaded_error" es el que corresponde al mensaje "Overloaded".
const RETRYABLE_ERROR_TYPES = new Set(["overloaded_error", "api_error", "rate_limit_error"]);
const ANALIZAR_MAX_INTENTOS = 3;
// Backoff entre intentos (configurable por env var solo para acelerar los tests automatizados)
const ANALIZAR_REINTENTO_MS = process.env.ANALIZAR_RETRY_MS_TEST
  ? JSON.parse(process.env.ANALIZAR_RETRY_MS_TEST)
  : [2000, 5000];

app.post("/api/analizar", requireAuth, async (req, res) => {
  const API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!API_KEY) {
    return res.status(500).json({ error: "API key no configurada en el servidor" });
  }

  try {
    let data, response;
    for (let intento = 0; intento < ANALIZAR_MAX_INTENTOS; intento++) {
      response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": API_KEY,
          "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify(req.body)
      });
      data = await response.json();

      const tipoError = data?.error?.type;
      const esUltimoIntento = intento === ANALIZAR_MAX_INTENTOS - 1;
      if (tipoError && RETRYABLE_ERROR_TYPES.has(tipoError) && !esUltimoIntento) {
        await sleep(ANALIZAR_REINTENTO_MS[intento] || 5000);
        continue;
      }
      break;
    }
    res.status(response.status).json(data);
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

app.post("/api/historial/eliminar", requireAuth, requireGestion, async (req, res) => {
  if (!GITHUB_TOKEN) {
    return res.status(500).json({ error: "GITHUB_TOKEN no configurado en el servidor" });
  }
  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ error: "ID requerido" });
    const { items, sha } = await leerHistorialDeGitHub();
    const nuevoItems = items.filter(i => i.id !== id);
    const nuevoContenido = Buffer.from(JSON.stringify(nuevoItems, null, 2)).toString("base64");

    const putRes = await fetch(GITHUB_API, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: `Historial: baja de análisis ${id}`,
        content: nuevoContenido,
        sha
      })
    });
    if (!putRes.ok) throw new Error(`GitHub API ${putRes.status}: ${await putRes.text()}`);

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
