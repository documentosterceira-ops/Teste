const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const cookieSession = require("cookie-session");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
require("dotenv").config();
const { query } = require("./db");
const { csrfTokenRoute, csrfProtect } = require("./csrf-mw");

// tenta usar bcrypt nativo; se falhar, usa bcryptjs
let bcrypt;
try { bcrypt = require("bcrypt"); } catch { bcrypt = require("bcryptjs"); }

const app = express();
const isProd = process.env.NODE_ENV === "production";

// Segurança base
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Sessão stateless via JWT httpOnly
app.use(cookieSession({
  name: "sid",
  keys: [process.env.JWT_SECRET],
  httpOnly: true,
  sameSite: "lax",
  secure: isProd,
  maxAge: 1000 * 60 * 60 * 8
}));

// Helpers de auth
function issueToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "8h" });
}
function requireAuth(req, res, next) {
  const token = req.session?.token;
  if (!token) return res.redirect("/login");
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.redirect("/login");
  }
}

// Rate-limit para login/registro
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

// Validação de senha
function isStrongPassword(pw) {
  return typeof pw === "string" && pw.length >= 8 && /[A-Za-z]/.test(pw) && /\d/.test(pw);
}

// Páginas
app.get("/login", (_, res) => res.sendFile(path.join(__dirname, "views", "login.html")));
app.get("/registrar", (_, res) => res.sendFile(path.join(__dirname, "views", "registrar.html")));
app.get("/", requireAuth, (_, res) => res.sendFile(path.join(__dirname, "views", "home.html")));

// CSRF
app.get("/csrf-token", csrfTokenRoute);

// Registrar
app.post("/registrar", authLimiter, csrfProtect, async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha || !isStrongPassword(senha)) {
      return res.status(400).send("Dados inválidos");
    }
    const exists = await query("SELECT 1 FROM users WHERE email = $1", [email.toLowerCase()]);
    if (exists.rows.length > 0) return res.status(409).send("E-mail já cadastrado");

    const hash = await bcrypt.hash(senha, 12);
    await query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
      [uuidv4(), email.toLowerCase(), hash]);

    res.redirect("/login");
  } catch (e) {
    console.error("ERRO /registrar:", e);
    res.status(500).send("Erro no cadastro");
  }
});

// Login
app.post("/login", authLimiter, csrfProtect, async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).send("Dados inválidos");

    const out = await query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    const user = out.rows[0];
    if (!user) return res.status(401).send("Usuário ou senha inválidos");

    const ok = await bcrypt.compare(senha, user.password_hash);
    if (!ok) return res.status(401).send("Usuário ou senha inválidos");

    req.session.token = issueToken({ id: user.id, email: user.email });
    res.redirect("/");
  } catch (e) {
    console.error("ERRO /login:", e);
    res.status(500).send("Erro no login");
  }
});

// Logout
app.post("/logout", csrfProtect, (req, res) => {
  req.session = null;
  res.redirect("/login");
});

// Health
app.get("/health", (_, res) => res.send("ok"));

// Start
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
