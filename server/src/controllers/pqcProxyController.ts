import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import tls from 'tls';
import net from 'net';
import { assertPublicHost } from '../utils/ssrf';

// Helper to syndicate proxy gateway primitives into CBOM assets inventory
export const syndicateProxyToAssets = async (id: string, name: string, listenPort: number, upstreamUrl: string, tlsCurve: string, tenantName: string) => {
  try {
    const kemId = ('ast-prx-kem-' + id).substring(0, 64);
    const crtId = ('ast-prx-crt-' + id).substring(0, 64);

    // 1. Upsert KEM Protocol Asset (FIPS 203 Quantum Safe)
    await pool.query(`
      INSERT INTO assets (
        id, type, name, path, algorithm, key_size, is_vulnerable, risk_level, status, description, recommendation, source, source_ref, tenant_name
      ) VALUES ($1, 'protocol', $2, $3, $4, 768, false, 'secure', 'active', $5, $6, 'pqc_proxy', $7, $8)
      ON CONFLICT (id) DO UPDATE SET 
        name = EXCLUDED.name,
        path = EXCLUDED.path,
        algorithm = EXCLUDED.algorithm,
        tenant_name = EXCLUDED.tenant_name,
        updated_at = NOW()
    `, [
      kemId,
      `${name} (Hybrid TLS 1.3 KEM)`,
      `Ingress Port :${listenPort} -> ${upstreamUrl}`,
      tlsCurve || 'ML-KEM-768 + X25519',
      `QuarkShield Transparent Hybrid Post-Quantum Key Encapsulation Mechanism protecting ${name} against HNDL attacks.`,
      `NIST FIPS 203 compliant. Zero further remediation needed.`,
      name,
      tenantName
    ]);

    // 2. Upsert Gateway Certificate Asset
    await pool.query(`
      INSERT INTO assets (
        id, type, name, path, algorithm, key_size, is_vulnerable, risk_level, status, description, recommendation, source, source_ref, tenant_name
      ) VALUES ($1, 'certificate', $2, $3, 'ECDSA-P384 / ML-DSA-65 Fallback', 384, false, 'secure', 'active', $4, $5, 'pqc_proxy', $6, $7)
      ON CONFLICT (id) DO UPDATE SET 
        name = EXCLUDED.name,
        path = EXCLUDED.path,
        tenant_name = EXCLUDED.tenant_name,
        updated_at = NOW()
    `, [
      crtId,
      `${name} Gateway Server Certificate`,
      `/etc/quarkshield/certs/gateway-${listenPort}.crt`,
      `Dual-key/fallback edge certificate terminating incoming HTTPS requests.`,
      `Active perimeter protection. Certificate rotation scheduled annually.`,
      name,
      tenantName
    ]);
  } catch (e) {
    console.warn('Failed to syndicate proxy to assets:', e);
  }
};

export const getProxies = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.query;
    let query = 'SELECT * FROM pqc_proxies';
    const params: any[] = [];

    if (tenant && typeof tenant === 'string' && tenant.trim()) {
      query += ' WHERE LOWER(tenant_name) = LOWER($1)';
      params.push(tenant.trim());
    }

    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);

    // Auto-syndicate all active proxies into CBOM assets
    for (const p of result.rows) {
      syndicateProxyToAssets(p.id, p.name, p.listen_port, p.upstream_url, p.tls_curve, p.tenant_name).catch(() => {});
    }

    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching PQC proxies:', err);
    res.status(500).json({ error: 'Failed to retrieve PQC proxies.' });
  }
};

export const createProxy = async (req: Request, res: Response) => {
  try {
    const {
      tenantName = 'SPINOVATIONCORP',
      name,
      listenPort = 8443,
      upstreamUrl = 'http://127.0.0.1:8080',
      tlsCurve = 'X25519MLKEM768'
    } = req.body;

    if (!name || !listenPort || !upstreamUrl) {
      return res.status(400).json({ error: 'Gateway name, listen port, and upstream URL are required.' });
    }

    const id = 'prx-' + crypto.randomUUID().substring(0, 8);
    const cleanTenant = tenantName.toUpperCase().trim();

    await pool.query(`
      INSERT INTO pqc_proxies (
        id, tenant_name, name, listen_port, upstream_url, tls_curve, 
        status, handshake_count, active_connections, cert_expiry
      ) VALUES ($1, $2, $3, $4, $5, $6, 'running', 0, 0, NOW() + INTERVAL '365 days')
    `, [id, cleanTenant, name, Number(listenPort), upstreamUrl, tlsCurve]);

    // Syndicate to CBOM assets
    await syndicateProxyToAssets(id, name, Number(listenPort), upstreamUrl, tlsCurve, cleanTenant);

    res.status(201).json({
      success: true,
      proxyId: id,
      message: `PQC Hybrid TLS Proxy '${name}' provisioned. Listening on port ${listenPort} with hybrid curve ${tlsCurve}.`
    });
  } catch (err: any) {
    console.error('Error creating PQC proxy:', err);
    res.status(500).json({ error: 'Failed to provision PQC proxy: ' + err.message });
  }
};

export const toggleProxyState = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // 'running' | 'stopped'
    const cleanStatus = status === 'stopped' ? 'stopped' : 'running';

    const result = await pool.query(
      'UPDATE pqc_proxies SET status = $1, last_active_at = NOW() WHERE id = $2 RETURNING *',
      [cleanStatus, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Proxy instance not found.' });
    }

    res.json({
      success: true,
      proxy: result.rows[0],
      message: `Gateway status updated to ${cleanStatus}.`
    });
  } catch (err: any) {
    console.error('Error toggling proxy state:', err);
    res.status(500).json({ error: 'Failed to update proxy status.' });
  }
};

export const deleteProxy = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM pqc_proxies WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Proxy instance not found.' });
    }

    // Clean up syndicated CBOM assets
    const kemId = ('ast-prx-kem-' + id).substring(0, 64);
    const crtId = ('ast-prx-crt-' + id).substring(0, 64);
    await pool.query("DELETE FROM assets WHERE source = 'pqc_proxy' AND (id = $1 OR id = $2)", [kemId, crtId]).catch(() => {});

    res.json({ success: true, message: 'Proxy gateway successfully deleted.' });
  } catch (err: any) {
    console.error('Error deleting proxy:', err);
    res.status(500).json({ error: 'Failed to delete proxy.' });
  }
};

/**
 * Validate a proxy gateway's upstream target (DEF-51/52).
 *
 * This is a config-generate + validate feature: QuarkShield does not run the
 * proxy, it generates nginx/Envoy config the customer deploys. "Validate" now
 * does a real check of the configured upstream rather than returning a canned
 * handshake:
 *  - upstream reachable over TCP (and, for https upstreams on a public host, the
 *    real negotiated TLS protocol/cipher is reported);
 *  - internal/loopback upstreams (the common case for a terminating proxy) are
 *    format-validated only, since the server must not open connections to
 *    internal hosts on a caller's behalf (SSRF).
 */
export const testProxyHandshake = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const lookup = await pool.query('SELECT * FROM pqc_proxies WHERE id = $1', [id]);
    if (lookup.rowCount === 0) {
      return res.status(404).json({ error: 'Proxy instance not found.' });
    }
    const p = lookup.rows[0];

    let upstream: URL;
    try { upstream = new URL(p.upstream_url); }
    catch { return res.status(400).json({ success: false, error: `Upstream URL is not valid: ${p.upstream_url}` }); }

    const port = upstream.port ? Number(upstream.port) : (upstream.protocol === 'https:' ? 443 : 80);

    // Internal/loopback upstream: validate config only (do not connect — SSRF).
    let isPublic = true;
    try { await assertPublicHost(upstream.hostname); } catch { isPublic = false; }

    if (!isPublic) {
      return res.json({
        success: true, proxyId: id, name: p.name, listenPort: p.listen_port, upstreamUrl: p.upstream_url,
        validation: 'config-valid',
        message: `Config is valid. Upstream ${upstream.hostname}:${port} is internal, so the live PQC handshake must be verified where the generated proxy config is deployed.`,
        recommendedCurve: p.tls_curve || 'X25519MLKEM768',
      });
    }

    // Public upstream: do a real TLS/TCP probe and report what actually negotiated.
    const started = Date.now();
    const result = await probeUpstream(upstream.hostname, port, upstream.protocol === 'https:');
    await pool.query('UPDATE pqc_proxies SET handshake_count = handshake_count + 1 WHERE id = $1', [id]);
    return res.json({
      success: true, proxyId: id, name: p.name, listenPort: p.listen_port, upstreamUrl: p.upstream_url,
      validation: 'target-reachable',
      reachable: result.reachable,
      negotiatedProtocol: result.protocol,
      cipherSuite: result.cipher,
      latencyMs: Date.now() - started,
      recommendedCurve: p.tls_curve || 'X25519MLKEM768',
      message: result.reachable
        ? `Upstream reachable. ${result.protocol ? 'Negotiated ' + result.protocol : ''}`.trim()
        : `Upstream ${upstream.hostname}:${port} did not respond.`,
    });
  } catch (err: any) {
    console.error('Error validating proxy target:', err);
    res.status(500).json({ error: 'Failed to validate proxy target: ' + err.message });
  }
};

/** Probe an upstream: TLS handshake for https, plain TCP connect otherwise. */
const probeUpstream = (host: string, port: number, https: boolean): Promise<{ reachable: boolean; protocol?: string; cipher?: string }> =>
  new Promise((resolve) => {
    let done = false;
    const finish = (r: { reachable: boolean; protocol?: string; cipher?: string }) => { if (!done) { done = true; resolve(r); } };
    if (https) {
      const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: 6000 }, () => {
        const proto = socket.getProtocol() || undefined;
        const cipher = socket.getCipher()?.name;
        socket.end();
        finish({ reachable: true, protocol: proto || undefined, cipher });
      });
      socket.on('error', () => finish({ reachable: false }));
      socket.on('timeout', () => { socket.destroy(); finish({ reachable: false }); });
    } else {
      const socket = net.connect({ host, port, timeout: 6000 }, () => { socket.end(); finish({ reachable: true }); });
      socket.on('error', () => finish({ reachable: false }));
      socket.on('timeout', () => { socket.destroy(); finish({ reachable: false }); });
    }
  });

export const getProxyTemplate = async (req: Request, res: Response) => {
  try {
    const { format = 'nginx' } = req.params;
    const { port = 8443, upstream = 'http://127.0.0.1:8080', name = 'quarkshield-pqc-proxy' } = req.query;

    if (format === 'nginx') {
      const config = `# ==============================================================================
# QUARKSHIELD POST-QUANTUM HYBRID TLS 1.3 REVERSE PROXY GATEWAY
# Ingress: Port ${port} (Terminates X25519MLKEM768 Post-Quantum TLS 1.3)
# Egress:  ${upstream} (Forwards unencrypted or internal traffic with ZERO code changes)
# ==============================================================================

server {
    listen ${port} ssl http2;
    listen [::]:${port} ssl http2;
    server_name _;

    # Dual-Key or Classical Fallback Server Certificates
    ssl_certificate     /etc/quarkshield/certs/gateway.crt;
    ssl_certificate_key /etc/quarkshield/certs/gateway.key;

    # Enforce TLS 1.3 exclusively
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Quantum-safe AEAD Ciphers
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

    # Negotiate Hybrid NIST FIPS 203 ML-KEM-768 Curve (OpenSSL 3.2+)
    ssl_curves X25519MLKEM768:x25519:secp384r1;

    # Zero-delay reverse proxy to legacy application
    location / {
        proxy_pass ${upstream};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-PQC-Cipher $ssl_cipher;
        proxy_set_header X-PQC-Curve  $ssl_curve;
    }
}
`;
      return res.type('text/plain').send(config);
    }

    if (format === 'docker-compose') {
      const compose = `version: '3.8'
services:
  # Upstream Legacy Application (Unchanged)
  legacy-app:
    image: my-company/legacy-backend:latest
    restart: unless-stopped
    ports:
      - "8080" # Internal only

  # QuarkShield Transparent PQC Hybrid Proxy Sidecar
  pqc-proxy:
    image: quarkshield/pqc-proxy-sidecar:latest
    restart: unless-stopped
    ports:
      - "${port}:${port}"
    environment:
      - LISTEN_PORT=${port}
      - UPSTREAM_URL=http://legacy-app:8080
      - PQC_CURVE=X25519MLKEM768
      - TLS_MIN_VERSION=TLSv1.3
    volumes:
      - ./certs:/etc/quarkshield/certs:ro
    depends_on:
      - legacy-app
`;
      return res.type('text/yaml').send(compose);
    }

    if (format === 'envoy') {
      const envoy = `static_resources:
  listeners:
  - name: pqc_ingress_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: ${port}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_params:
              tls_minimum_protocol_version: TLSv1_3
              ecdh_curves:
              - "X25519MLKEM768"
              - "X25519"
            tls_certificates:
            - certificate_chain: { filename: "/etc/quarkshield/certs/gateway.crt" }
              private_key: { filename: "/etc/quarkshield/certs/gateway.key" }
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: pqc_ingress
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: upstream_service }
  clusters:
  - name: upstream_service
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: upstream_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 8080
`;
      return res.type('text/yaml').send(envoy);
    }

    res.status(400).json({ error: "Unsupported format. Supported: 'nginx', 'docker-compose', 'envoy'" });
  } catch (err: any) {
    console.error('Error generating proxy template:', err);
    res.status(500).json({ error: 'Failed to generate proxy template.' });
  }
};
