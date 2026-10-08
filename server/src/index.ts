import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import crypto from 'crypto';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import pool, { initDb } from './config/db';

// A rejected promise inside an Express 4 async handler is not caught by Express and
// would terminate the Node 15+ process. Log it and keep serving.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
});
process.on('uncaughtException', (err) => {
  // State is undefined after an uncaught exception: log and let the supervisor
  // (docker restart: unless-stopped) bring up a clean process.
  console.error('Uncaught exception, exiting:', err);
  setTimeout(() => process.exit(1), 100).unref();
});
import { bootstrapAdmin } from './config/bootstrap';
import routes from './routes/routes';
import { attachUser, isWeakSecret } from './middleware/auth';
import { logDownload } from './lib/downloadTracker';
import { startPullScheduler } from './lib/pullScheduler';

dotenv.config();

const app = express();
app.set('trust proxy', 1);
const port = process.env.PORT || 5050;

// Restrict CORS to configured origins when provided; credentials enabled so the
// session cookie is sent cross-subdomain. ALLOWED_ORIGINS is comma-separated;
// if unset, reflect the request origin (dev convenience).
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction && allowedOrigins.length === 0) {
  console.warn('ALLOWED_ORIGINS is not set: cross-origin browser requests will be refused (same-origin only).');
}
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // same-origin / curl
    // Never reflect an arbitrary origin with credentials in production.
    if (allowedOrigins.length === 0) return cb(null, !isProduction);
    return cb(null, allowedOrigins.includes(origin));
  },
  credentials: true,
}));
// Security headers. CSP is disabled here because the SPA/index.html is served
// by this same app and a strict default CSP would block its inline assets;
// enable a tuned CSP once the frontend asset origins are enumerated.
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
// Stripe webhook signature verification requires raw body buffer
app.use('/api/billing/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(cookieParser());
app.use(attachUser);

// Rate limit authentication endpoints to blunt credential stuffing / brute force
// and password-reset abuse (DEF-04).
// Each concern gets its OWN limiter instance (separate buckets): a NAT'd office
// submitting support forms must not consume the login budget, and a fleet of agents
// behind one egress IP must not throttle each other.
const perIpLimiter = (max: number, windowMs: number, message: string) => rateLimit({
  windowMs,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: message },
});
const FIFTEEN_MIN = 15 * 60 * 1000;
const TEN_MIN = 10 * 60 * 1000;
const tooMany = 'Too many attempts. Please wait a few minutes and try again.';
app.use('/api/auth/login', perIpLimiter(30, FIFTEEN_MIN, tooMany));
app.use('/api/auth/forgot-password', perIpLimiter(15, FIFTEEN_MIN, tooMany));
app.use('/api/auth/reset-password', perIpLimiter(15, FIFTEEN_MIN, tooMany));
app.use('/api/auth/change-password', perIpLimiter(15, FIFTEEN_MIN, tooMany));
app.use('/api/2fa', perIpLimiter(30, FIFTEEN_MIN, tooMany));
app.use('/api/scan/license/verify', perIpLimiter(120, FIFTEEN_MIN, tooMany));
app.use('/api/billing/checkout', perIpLimiter(20, FIFTEEN_MIN, tooMany));
app.use('/api/assessment', perIpLimiter(10, FIFTEEN_MIN, tooMany));
app.use('/api/support', perIpLimiter(10, FIFTEEN_MIN, tooMany));
app.use('/api/probe', perIpLimiter(60, TEN_MIN, 'Too many probe requests. Please slow down.'));
app.use('/api/git/ci-gate/evaluate', perIpLimiter(120, TEN_MIN, 'Too many CI gate evaluations. Please slow down.'));

// Agent endpoints: keyed by the fleet token / license key when one is presented
// (so hundreds of machines behind one corporate NAT each get their own bucket, and a
// single stolen token still cannot hammer the database), else by source IP.
const agentKey = (req: express.Request): string => {
  const auth = req.headers.authorization;
  const bearer = auth && auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const tok = String(req.headers['x-connector-token'] || bearer || req.body?.token || req.body?.licenseKey || req.body?.license_key || '').trim();
  if (tok) return 'tok:' + crypto.createHash('sha256').update(tok).digest('hex').slice(0, 24);
  return 'ip:' + ipKeyGenerator(req.ip || '');
};
const agentLimiter = rateLimit({
  windowMs: TEN_MIN,
  // ~one poll every 2 min + syncs per machine; a token is shared by a whole fleet,
  // so allow for large fleets while still bounding abuse.
  max: 3000,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: agentKey,
  message: { error: 'Too many agent requests for this token. Please slow down.' },
});
app.use('/api/scan/agent/ingest', agentLimiter);
app.use('/api/scan/agent/commands', agentLimiter);
app.use('/api/scan/adcs/report', agentLimiter);

// Determine and serve compiled agent downloads
const possibleDownloadPaths = [
  process.env.DOWNLOADS_DIR,
  path.join(__dirname, '../../agent/binaries'),
  path.join(__dirname, '../binaries'),
  path.join(__dirname, '../../downloads'),
  path.join(process.cwd(), 'agent/binaries'),
  path.join(process.cwd(), 'downloads')
].filter(Boolean) as string[];

let downloadsDir = possibleDownloadPaths.find(p => fs.existsSync(p)) || path.join(__dirname, '../../agent/binaries');
// Track agent-binary downloads (OS + geo) before serving the file. Only logs actual
// file requests (path has an extension), so directory hits aren't counted. Fire-and-forget.
app.use('/downloads', (req, _res, next) => {
  const f = req.path.replace(/^\/+/, '');
  if (f && /\.[a-z0-9]+$/i.test(f)) logDownload(req, f);
  next();
});
app.use('/downloads', express.static(downloadsDir, {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// API Routes.
// Force no-store on every API response so no CDN/proxy (e.g. a Cloudflare
// "Cache Everything" rule) can cache an authenticated response and serve one
// user's data or session to another. Auth responses also set Set-Cookie, which
// must never be cached by an intermediary.
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});
app.use('/api', routes);

// Health check: reports the real database state so deploys and uptime monitors
// cannot see "ok" while every API call is failing.
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'ok', service: 'desktop-pqc-scanner-api', version: '2.0.0' });
  } catch (e) {
    res.status(503).json({ status: 'degraded', database: 'unreachable', service: 'desktop-pqc-scanner-api', version: '2.0.0' });
  }
});

// Final API error handler: never leak stack traces or internal messages to clients,
// and make sure an async handler that throws cannot leave the request hanging.
app.use('/api', (err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled API error:', err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

// Determine and serve React frontend UI
const possibleUiPaths = [
  process.env.UI_DIST_DIR,
  path.join(__dirname, '../../ui/dist'),
  path.join(__dirname, '../ui_dist'),
  path.join(__dirname, '../ui/dist'),
  path.join(process.cwd(), 'ui/dist'),
  path.join(process.cwd(), 'dist')
].filter(Boolean) as string[];

const uiDistDir = possibleUiPaths.find(p => fs.existsSync(p));
// Unknown /api and /downloads paths must 404 rather than fall through to the SPA
// (DEF-14): returning index.html with a 200 made broken links look like they work.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/downloads/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  next();
});

if (uiDistDir) {
  console.log(`Serving Web UI from: ${uiDistDir}`);
  app.use(express.static(uiDistDir));
  app.get('*', (req, res) => {
    res.sendFile(path.join(uiDistDir, 'index.html'));
  });
} else {
  console.log('Frontend UI dist directory not detected; running in API-only mode.');
}

import https from 'https';

// Helper to start both HTTP and HTTPS listeners
const startServers = () => {
  // DEF-41: start the recurring pull scheduler (60s worker) once the app boots.
  startPullScheduler();

  // 1. Start HTTP Server
  app.listen(port, () => {
    console.log(`=======================================================`);
    console.log(` 🛡️ Desktop & Host PQC Vulnerability Scanner Console`);
    console.log(` HTTP server active on port ${port}`);
    console.log(` Downloads served from: ${downloadsDir}`);
    console.log(` Ingestion endpoint: POST /api/scan/agent/ingest`);
    console.log(`=======================================================`);
  });

  // 2. Start HTTPS Server (if SSL certificates exist)
  const httpsPort = process.env.HTTPS_PORT || 5443;
  const possibleCertPaths = [
    process.env.SSL_CERT_PATH,
    path.join(__dirname, '../certs/cert.pem'),
    path.join(__dirname, '../../certs/cert.pem'),
    path.join(process.cwd(), 'certs/cert.pem'),
    path.join(process.cwd(), 'server/certs/cert.pem')
  ].filter(Boolean) as string[];

  const possibleKeyPaths = [
    process.env.SSL_KEY_PATH,
    path.join(__dirname, '../certs/key.pem'),
    path.join(__dirname, '../../certs/key.pem'),
    path.join(process.cwd(), 'certs/key.pem'),
    path.join(process.cwd(), 'server/certs/key.pem')
  ].filter(Boolean) as string[];

  const certPath = possibleCertPaths.find(p => fs.existsSync(p));
  const keyPath = possibleKeyPaths.find(p => fs.existsSync(p));

  if (certPath && keyPath) {
    try {
      const credentials = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
      https.createServer(credentials, app).listen(httpsPort, () => {
        console.log(`🔒 HTTPS server active on port ${httpsPort} (Cloudflare Full SSL enabled)`);
      });
    } catch (e) {
      console.warn('Could not initialize HTTPS listener:', e);
    }
  } else {
    console.log('ℹ️ No SSL certificates detected; running HTTP-only mode (Cloudflare Flexible mode).');
  }
};

// Fail closed at BOOT (not lazily on the first request) when a production server is
// configured with a missing/weak/placeholder secret.
if (process.env.NODE_ENV === 'production') {
  const bad: string[] = [];
  if (isWeakSecret(process.env.JWT_SECRET)) bad.push('JWT_SECRET');
  if (isWeakSecret(process.env.LICENSE_SIGNING_SECRET)) bad.push('LICENSE_SIGNING_SECRET');
  if (bad.length) {
    console.error(`Refusing to start: ${bad.join(', ')} missing, shorter than 32 chars, or a placeholder. Generate with: openssl rand -hex 32`);
    process.exit(1);
  }
}

// Warn loudly when secondary encryption keys fall back to JWT_SECRET: rotating the
// JWT secret would then make every stored 2FA secret and connector credential
// undecryptable. Set dedicated keys before go-live.
if (process.env.NODE_ENV === 'production') {
  if (!process.env.TWO_FACTOR_ENC_KEY) console.warn('TWO_FACTOR_ENC_KEY is unset; TOTP secrets are encrypted with JWT_SECRET. Set a dedicated key.');
  if (!process.env.CONNECTOR_ENC_KEY) console.warn('CONNECTOR_ENC_KEY is unset; connector credentials are encrypted with JWT_SECRET. Set a dedicated key.');
}

// Initialize database & start server
initDb()
  .then(() => bootstrapAdmin())
  .then(() => {
    startServers();
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    startServers();
  });

