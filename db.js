// db.js — conexão Neon via HTTP (Render não tem inspeção TLS, então normal)
require("dotenv").config();
const { neon, neonConfig } = require("@neondatabase/serverless");

// força uso de fetch HTTP (sem WebSocket)
neonConfig.poolQueryViaFetch = true;

const sql = neon(process.env.DATABASE_URL);

// Usa placeholders $1, $2...
async function query(text, params = []) {
  return sql.query(text, params);
}

module.exports = { sql, query };
