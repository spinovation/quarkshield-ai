import { Pool } from 'pg';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_DATABASE || 'quarkshield_scanner',
  password: process.env.DB_PASSWORD || 'postgres',
  port: Number(process.env.DB_PORT) || 5432,
  connectionTimeoutMillis: 2000,
});

/**
 * Split a SQL script into individual statements on top-level semicolons.
 * Single-quoted string literals are respected so semicolons inside values
 * are not treated as terminators. The schema contains no dollar-quoted
 * blocks or stored functions, so this is sufficient.
 */
const splitSqlStatements = (sql: string): string[] => {
  const statements: string[] = [];
  let current = '';
  let inSingleQuote = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === "'") {
      if (inSingleQuote && sql[i + 1] === "'") {
        current += "''";
        i++;
        continue;
      }
      inSingleQuote = !inSingleQuote;
      current += ch;
      continue;
    }
    if (ch === ';' && !inSingleQuote) {
      const trimmed = current.trim();
      if (trimmed) statements.push(trimmed);
      current = '';
      continue;
    }
    current += ch;
  }
  const tail = current.trim();
  if (tail) statements.push(tail);
  return statements;
};

export const initDb = async () => {
  let client;
  try {
    client = await pool.connect();
    console.log('Connected to PostgreSQL successfully.');
  } catch (err) {
    console.error('Database connection error:', err);
    // Don't crash immediately; allows the container DB time to start up.
    return;
  }

  try {
    const schemaPath = path.join(__dirname, '../models/schema.sql');
    if (!fs.existsSync(schemaPath)) {
      console.warn('Warning: schema.sql file not found at', schemaPath);
      return;
    }

    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    const statements = splitSqlStatements(schemaSql);

    // Run each statement independently. A single out-of-order or already-applied
    // statement must not abort the whole migration. Previously the file ran as
    // one implicit transaction, so the first error rolled everything back and a
    // fresh database was left with no tables at all. Every statement is
    // idempotent (IF NOT EXISTS / ON CONFLICT), so re-runs are safe.
    let applied = 0;
    let failed = 0;
    for (const stmt of statements) {
      try {
        await client.query(stmt);
        applied++;
      } catch (stmtErr: any) {
        failed++;
        const preview = stmt.replace(/\s+/g, ' ').slice(0, 80);
        console.warn(`Schema statement skipped (${stmtErr.code || 'error'}): ${preview}...`);
      }
    }
    console.log(`Database schema applied: ${applied} statements ok, ${failed} skipped.`);
  } catch (err) {
    console.error('Schema initialization error:', err);
  } finally {
    client.release();
  }
};

export default pool;
