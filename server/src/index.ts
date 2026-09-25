import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { initDb } from './config/db';
import { bootstrapAdmin } from './config/bootstrap';
import routes from './routes/routes';
import { attachUser } from './middleware/auth';

dotenv.config();

const app = express();
const port = process.env.PORT || 5050;

// Restrict CORS to configured origins when provided; credentials enabled so the
// session cookie is sent cross-subdomain. ALLOWED_ORIGINS is comma-separated;
// if unset, reflect the request origin (dev convenience).
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // same-origin / curl
    if (allowedOrigins.length === 0) return cb(null, true);
    return cb(null, allowedOrigins.includes(origin));
  },
  credentials: true,
}));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(cookieParser());
app.use(attachUser);

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
app.use('/downloads', express.static(downloadsDir, {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// API Routes
app.use('/api', routes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'desktop-pqc-scanner-api', version: '2.0.0' });
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

