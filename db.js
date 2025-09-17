// db.js — Conexão Neon via HTTP (Render)
require("dotenv").config();
const { neon, neonConfig } = require("@neondatabase/serverless");

// força uso via fetch/HTTPS (sem WebSocket)
neonConfig.poolQueryViaFetch = true;

const sql = neon(process.env.DATABASE_URL);

/**
 * Executa query com placeholders ($1, $2, ...) e
 * SEMPRE retorna no formato { rows: [...] }.
 */
async function query(text, params = []) {
  const r = await sql.query(text, params);
  if (Array.isArray(r)) return { rows: r };  // normaliza caso venha como array
  return r;                                   // já está no formato { rows, fields }
}

module.exports = { sql, query };
