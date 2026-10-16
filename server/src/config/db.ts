import { Pool } from 'pg';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

if (process.env.NODE_ENV === 'production' && !process.env.DB_PASSWORD) {
  // Never connect to a production database with the postgres default password.
  throw new Error('DB_PASSWORD is not set (required in production).');
}

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_DATABASE || 'quarkshield_scanner',
  password: process.env.DB_PASSWORD || 'postgres',
  port: Number(process.env.DB_PORT) || 5432,
  // 2s was too aggressive right after a container recreation (the console opened its
  // pool before Postgres had finished accepting connections, so the first requests
  // 520'd). 5s rides out that warmup window.
  connectionTimeoutMillis: 5000,
  // Keep TCP alive so a connection dropped by the OS/NAT is detected, and recycle idle
  // connections so a stale socket (e.g. to a just-recreated DB container) is not reused.
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
  idleTimeoutMillis: 30000,
});

// A backend error on an IDLE pooled client surfaces as an 'error' event on the pool.
// Without a listener, Node treats it as unhandled and crashes the whole process — which
// is exactly how a transient DB blip became a 520 across every request. Log and drop the
// dead client; the pool opens a fresh one on the next query.
pool.on('error', (err) => {
  console.warn('[db pool] idle client error (recovered):', err.message);
});

// Write-safe single retry: ONLY when a query fails to acquire a connection (connect-phase
// pool errors), which guarantees the statement never reached Postgres — so retrying can
// never double a write. A mid-query drop is NOT retried here.
const CONNECT_PHASE_ERROR = /Connection terminated due to connection timeout|timeout exceeded when trying to connect/i;
const RETRY_DELAY_MS = 300;
const originalQuery = pool.query.bind(pool);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(pool as any).query = async (...args: any[]): Promise<any> => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return await (originalQuery as any)(...args);
  } catch (err) {
    if (CONNECT_PHASE_ERROR.test(String((err as Error)?.message || ''))) {
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return await (originalQuery as any)(...args);
    }
    throw err;
  }
};

/**
 * Split a SQL script into individual statements on top-level semicolons.
 * Single-quoted string literals AND `--` line comments are respected, so a
 * semicolon inside a value or inside a comment is not treated as a statement
 * terminator. The schema contains no dollar-quoted blocks or stored functions,
 * so this is sufficient.
 */
const splitSqlStatements = (sql: string): string[] => {
  const statements: string[] = [];
  let current = '';
  let inSingleQuote = false;
  let inLineComment = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];

    // Inside a -- line comment: consume (keep for readability) until newline.
    if (inLineComment) {
      current += ch;
      if (ch === '\n') inLineComment = false;
      continue;
    }

    // Start of a -- line comment (only outside a string literal).
    if (!inSingleQuote && ch === '-' && sql[i + 1] === '-') {
      inLineComment = true;
      current += ch;
      continue;
    }

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
      pushStatement(statements, current);
      current = '';
      continue;
    }
    current += ch;
  }
  pushStatement(statements, current);
  return statements;
};

/** Push a statement unless it is empty or contains only whitespace/comments. */
const pushStatement = (statements: string[], raw: string): void => {
  const trimmed = raw.trim();
  if (!trimmed) return;
  // Ignore chunks that are only line comments (e.g. a trailing comment after ';').
  const withoutComments = trimmed.replace(/--[^\n]*/g, '').trim();
  if (!withoutComments) return;
  statements.push(trimmed);
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
