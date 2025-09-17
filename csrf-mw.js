const Tokens = require("csrf");
const tokens = new Tokens();

function ensureSecret(req) {
  if (!req.session) throw new Error("Sessão indisponível");
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = process.env.CSRF_SECRET || tokens.secretSync();
  }
}

function csrfTokenRoute(req, res) {
  try {
    ensureSecret(req);
    const token = tokens.create(req.session.csrfSecret);
    // evita cache em CDN/navegador
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.set("Pragma", "no-cache");
    res.json({ csrfToken: token });
  } catch {
    res.status(500).send("Sessão indisponível");
  }
}


function csrfProtect(req, res, next) {
  try {
    ensureSecret(req);
  } catch {
    return res.status(500).send("Sessão indisponível");
  }
  const sent = req.body?._csrf || req.headers["x-csrf-token"] || req.query?._csrf;
  if (!sent) return res.status(403).send("CSRF ausente");
  const ok = tokens.verify(req.session.csrfSecret, sent);
  if (!ok) return res.status(403).send("CSRF inválido");
  next();
}

module.exports = { csrfTokenRoute, csrfProtect };

