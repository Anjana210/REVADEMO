require('dotenv').config();
const express = require('express');
const app = express();
const path = require('node:path');
const http = require('http');
const os = require('os');
const tls = require('tls');
const { exec } = require('child_process');
// const PDFDocument = require('pdfkit');
// const fs = require('fs');
const { Server } = require("socket.io");
// const axios = require('axios'); // Removed
const cors = require('cors');
const session = require('express-session');
//const puppeteer = require('puppeteer');
//const puppeteer = require('puppeteer-core'); // Use the core version
const puppeteer = require('puppeteer');
//const chromium = require('@sparticuz/chromium'); // Use Vercel-compatible chromium 
// Use PORT from environment (cloud platforms like Railway, Render set this)
const port = process.env.PORT || 4000;
const ejs = require('ejs'); 
const bcrypt = require('bcryptjs');

const { Pool } = require('pg'); // --- ADDED --- (Step 1: Import the Pool)

const pool = new Pool(); // --- ADDED --- (Step 2: Initialize the Pool)
app.set('view engine', 'ejs');
app.use(cors({ origin: true }));
// NOTE: On Linux (Railway), filesystem is case-sensitive. All static assets live under 'Public'.
app.use(express.static(path.join(__dirname, 'Public')));
// Explicitly serve uploads (including seeded company-logo) from 'Public/uploads'.
app.use('/uploads', express.static(path.join(__dirname, 'Public', 'uploads')));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'a-secure-secret-key-for-revartix',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

const { requireAdmin, requireCustomer, requireStaff, requireMaster, requireWrite, requireSuperAdmin } = require('./middleware.js');

// --- Ensure REVA ZONE Control Center schema exists and seed initial data ---
async function ensureControlCenterSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Enums (compat with older Postgres versions without IF NOT EXISTS for TYPE)
    await client.query(`
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'company_status') THEN
          CREATE TYPE company_status AS ENUM('Active','Suspended','Trial','Cancelled');
        END IF;
      END $$;`);
    await client.query(`
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'db_health') THEN
          CREATE TYPE db_health AS ENUM('Healthy','Warning','Critical');
        END IF;
      END $$;`);

    // companies (create if not exists; fallback to minimal if a different schema already exists)
    await client.query(`
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='companies') THEN
          CREATE TABLE companies (
            id SERIAL PRIMARY KEY,
            company_name VARCHAR(255) UNIQUE NOT NULL,
            reva_platform_id VARCHAR(50) UNIQUE,
            address TEXT,
            contact_email VARCHAR(100),
            phone VARCHAR(50),
            status company_status DEFAULT 'Active',
            date_registered TIMESTAMP NOT NULL DEFAULT NOW(),
            last_activity_at TIMESTAMP,
            suspension_message TEXT
          );
        END IF;
      END $$;`);

    // Add suspension_message column if missing
    await client.query(`
      DO $$ BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns WHERE table_name='companies' AND column_name='suspension_message'
        ) THEN
          ALTER TABLE companies ADD COLUMN suspension_message TEXT;
        END IF;
      END $$;`);

    // subscription_plans
    await client.query(`
      CREATE TABLE IF NOT EXISTS subscription_plans (
        id SERIAL PRIMARY KEY,
        plan_name VARCHAR(50) UNIQUE NOT NULL,
        max_customers INT NOT NULL,
        max_data_transfer_gb INT DEFAULT 10,
        price_usd DECIMAL(10,2)
      );`);

    // company_licenses
    await client.query(`
      CREATE TABLE IF NOT EXISTS company_licenses (
        id SERIAL PRIMARY KEY,
        company_id INT REFERENCES companies(id) ON DELETE CASCADE,
        license_code VARCHAR(10) UNIQUE NOT NULL,
        plan_id INT REFERENCES subscription_plans(id),
        udo_reference_string VARCHAR(255),
        start_date DATE NOT NULL,
        expiry_date DATE NOT NULL,
        is_paid BOOLEAN DEFAULT TRUE
      );`);

    // customer_accounts: end-user accounts linked to companies
    await client.query(`
      CREATE TABLE IF NOT EXISTS customer_accounts (
        id SERIAL PRIMARY KEY,
        company_id INT REFERENCES companies(id) ON DELETE CASCADE,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        last_login_at TIMESTAMP
      );`);

    // system_instances
    await client.query(`
      CREATE TABLE IF NOT EXISTS system_instances (
        id SERIAL PRIMARY KEY,
        company_id INT UNIQUE REFERENCES companies(id) ON DELETE CASCADE,
        platform_version VARCHAR(20) NOT NULL,
        db_status db_health DEFAULT 'Healthy',
        server_uptime_hours INT,
        current_transfer_gb DECIMAL(10,2) DEFAULT 0.00,
        last_health_check TIMESTAMP
      );`);

    // admin_audit_logs
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id SERIAL PRIMARY KEY,
        admin_user_id INT NOT NULL,
        company_id INT REFERENCES companies(id) ON DELETE SET NULL,
        action_type VARCHAR(100) NOT NULL,
        details TEXT,
        timestamp TIMESTAMP NOT NULL DEFAULT NOW()
      );`);

    // user_activity_logs (monitoring)
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_activity_logs (
        id SERIAL PRIMARY KEY,
        company_id INT REFERENCES companies(id) ON DELETE CASCADE,
        user_id INT,
        action_type VARCHAR(50),
        timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
        ip_address VARCHAR(50),
        latitude DECIMAL(10,8),
        longitude DECIMAL(11,8)
      );`);

    // Seed plans
    await client.query(`INSERT INTO subscription_plans (plan_name, max_customers, max_data_transfer_gb, price_usd)
      VALUES 
        ('Basic', 500, 10, 19.00),
        ('Pro', 2000, 50, 49.00),
        ('Demo', 100, 5, 0.00)
      ON CONFLICT (plan_name) DO NOTHING;`);

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('ensureControlCenterSchema failed:', e);
  } finally {
    client.release();
  }
}

ensureControlCenterSchema().catch(() => {});

// Aliases using "manage" path as requested, redirecting to the canonical routes
app.get('/admin/control-center/manage/:companyId', requireSuperAdmin, (req, res) => {
  const id = Number(req.params.companyId);
  return res.redirect(`/admin/control-center/company/${id}`);
});

// --- System Health Helpers ---
const HEALTH_DEFAULT_TIMEOUT_MS = 3000;
const meterApiHealthUrl = process.env.METER_API_HEALTH_URL || process.env.METER_API_BASE;
const jobsHealthUrl = process.env.JOBS_HEALTH_URL; // optional

const timeoutFetch = async (url, timeoutMs = HEALTH_DEFAULT_TIMEOUT_MS) => {
  if (!url) throw new Error('Health URL not configured');
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, method: 'GET' });
    return { ok: res.ok, status: res.status };
  } finally {
    clearTimeout(id);
  }
};

const mapByLatency = (ok, ms) => {
  if (!ok) return 'down';
  if (ms < 300) return 'healthy';
  if (ms < 1000) return 'operational';
  return 'degraded';
};

// --- New Health Checks ---
async function checkDisk() {
  const start = Date.now();
  try {
    if (process.platform === 'win32') {
      const drive = (process.env.SystemDrive || 'C:').replace(/\\$/,'');
      const cmd = `wmic logicaldisk where DeviceID='${drive}' get FreeSpace,Size /format:value`;
      const { free, size } = await new Promise((resolve, reject) => {
        exec(cmd, { windowsHide: true }, (err, stdout) => {
          if (err) return reject(err);
          const mFree = stdout.match(/FreeSpace=(\d+)/i);
          const mSize = stdout.match(/Size=(\d+)/i);
          if (!mFree || !mSize) return reject(new Error('WMIC parse error'));
          resolve({ free: Number(mFree[1]), size: Number(mSize[1]) });
        });
      });
      const pct = size ? (free / size) * 100 : 0;
      const status = pct < 10 ? 'down' : pct < 20 ? 'degraded' : 'healthy';
      return { status, latency: Date.now() - start, message: `free=${pct.toFixed(1)}%` };
    } else {
      const { pct } = await new Promise((resolve, reject) => {
        exec('df -k .', (err, stdout) => {
          if (err) return reject(err);
          const lines = stdout.trim().split(/\r?\n/);
          const parts = lines[lines.length-1].split(/\s+/);
          const usedPctStr = parts[4] || '';
          const usedPct = Number(usedPctStr.replace('%','')) || 0;
          const freePct = 100 - usedPct;
          resolve({ pct: freePct });
        });
      });
      const status = pct < 10 ? 'down' : pct < 20 ? 'degraded' : 'healthy';
      return { status, latency: Date.now() - start, message: `free=${pct.toFixed(1)}%` };
    }
  } catch (e) {
    return { status: 'unknown', latency: null, message: e.message };
  }
}

// --- Customer-friendly Health Aggregation ---
async function checkBillEngine() {
  const start = Date.now();
  try {
    const { PDFDocument } = require('pdf-lib');
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([200, 100]);
    const bytes = await pdfDoc.save();
    const ok = bytes && bytes.length > 0;
    return { ok, ms: Date.now() - start };
  } catch (e) {
    return { ok: false, ms: null, err: e.message };
  }
}

async function getCustomerHealth() {
  const [db, disk, proc, clock, tls, bill] = await Promise.allSettled([
    checkDb(),
    checkDisk(),
    checkProcess(),
    checkClock(),
    checkTlsCert(),
    checkBillEngine()
  ]);

  const pick = (res, def) => (res.status === 'fulfilled' ? res.value : def);
  const dbR = pick(db, { status: 'unknown' });
  const diskR = pick(disk, { status: 'unknown', message: '' });
  const procR = pick(proc, { status: 'unknown', message: '' });
  const clockR = pick(clock, { status: 'unknown' });
  const tlsR = pick(tls, { status: 'unknown', message: '' });
  const billR = pick(bill, { ok: false, ms: null });

  // Core Service: DB healthy/operational AND process not down
  const coreOk = (dbR.status === 'healthy' || dbR.status === 'operational') && procR.status !== 'down';
  const core = coreOk ? 'healthy' : (procR.status === 'down' || dbR.status === 'down') ? 'down' : 'degraded';

  // CSV Storage: map disk free% thresholds already encoded in diskR.status
  const csv = diskR.status || 'unknown';

  // Bill Engine: successful quick PDF render
  const billStatus = billR.ok ? 'operational' : 'down';

  // Pending Jobs: if jobs_heartbeat exists we can’t infer pending; default 0 for this SKU
  const pendingJobs = 0;

  // Avg Processing Time: use bill engine + db latency as proxy
  const avgMs = ((billR.ms || 0) + (typeof dbR.latency === 'number' ? dbR.latency : 0)) || 0;
  const avgLabel = avgMs < 10000 ? '< 10 seconds' : '≥ 10 seconds';

  // Security: TLS cert not down and clock drift small
  const sec = (tlsR.status !== 'down' && clockR.status !== 'down') ? 'secure' : 'attention';

  return {
    core_service: { status: core },
    csv_storage: { status: csv },
    bill_engine: { status: billStatus },
    pending_jobs: { status: pendingJobs === 0 ? 'healthy' : 'degraded', value: pendingJobs },
    avg_processing: { status: avgMs < 10000 ? 'healthy' : 'degraded', label: avgLabel },
    security: { status: sec }
  };
}

app.get('/api/customer-health', requireStaff, async (req, res) => {
  try {
    const data = await getCustomerHealth();
    res.json({ status: 'success', data });
  } catch (e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

async function sampleCpuPercent(durationMs = 300) {
  const cores = os.cpus().length || 1;
  const startUsage = process.cpuUsage();
  const start = Date.now();
  await new Promise(r => setTimeout(r, durationMs));
  const elap = Date.now() - start;
  const usage = process.cpuUsage(startUsage);
  const totalMicros = usage.user + usage.system;
  const percent = (totalMicros / 1000) / (elap * cores) * 100;
  return Math.max(0, Math.min(100, percent));
}

async function checkProcess() {
  try {
    const rss = process.memoryUsage().rss;
    const totalMem = os.totalmem() || 1;
    const memPct = (rss / totalMem) * 100;
    const cpuPct = await sampleCpuPercent(300);
    const worst = Math.max(memPct, cpuPct);
    const status = worst >= 90 ? 'down' : worst >= 70 ? 'degraded' : 'healthy';
    const msg = `rss=${(rss/1024/1024).toFixed(0)}MB, mem=${memPct.toFixed(1)}%, cpu=${cpuPct.toFixed(1)}%`;
    return { status, latency: 300, message: msg };
  } catch (e) {
    return { status: 'unknown', latency: null, message: e.message };
  }
}

async function checkClock() {
  const start = Date.now();
  try {
    const resp = await fetch('https://worldtimeapi.org/api/ip');
    const ms = Date.now() - start;
    if (!resp.ok) return { status: 'unknown', latency: ms, message: `HTTP ${resp.status}` };
    const data = await resp.json();
    const serverSec = Date.now() / 1000;
    const apiSec = (data.unixtime != null) ? Number(data.unixtime) : (new Date(data.datetime)).getTime()/1000;
    const drift = Math.abs(serverSec - apiSec);
    const status = drift >= 10 ? 'down' : drift >= 2 ? 'degraded' : 'healthy';
    return { status, latency: ms, message: `drift=${drift.toFixed(2)}s` };
  } catch (e) {
    return { status: 'unknown', latency: null, message: e.message };
  }
}

async function checkTlsCert() {
  const start = Date.now();
  const hostEnv = process.env.TLS_CHECK_HOST; // e.g. mydomain.com:443
  if (!hostEnv) return { status: 'unknown', latency: null, message: 'TLS_CHECK_HOST not set' };
  try {
    const [host, portStr] = hostEnv.split(':');
    const port = Number(portStr || 443);
    const daysLeft = await new Promise((resolve, reject) => {
      const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
        try {
          const cert = sock.getPeerCertificate();
          sock.end();
          if (!cert || !cert.valid_to) return reject(new Error('No certificate'));
          const validTo = new Date(cert.valid_to).getTime();
          const days = Math.floor((validTo - Date.now()) / (1000*60*60*24));
          resolve(days);
        } catch (e) { reject(e); }
      });
      sock.on('error', reject);
    });
    const status = daysLeft <= 0 ? 'down' : daysLeft < 15 ? 'degraded' : 'healthy';
    return { status, latency: Date.now() - start, message: `expires_in=${daysLeft}d` };
  } catch (e) {
    return { status: 'unknown', latency: null, message: e.message };
  }
}

async function upsertHealth(service_key, status, latency_ms, message) {
  await pool.query(
    `INSERT INTO system_health(service_key, status, latency_ms, message, checked_at)
     VALUES ($1,$2,$3,$4, NOW())
     ON CONFLICT (service_key)
     DO UPDATE SET status=EXCLUDED.status, latency_ms=EXCLUDED.latency_ms, message=EXCLUDED.message, checked_at=EXCLUDED.checked_at`,
    [service_key, status, latency_ms ?? null, message ?? null]
  );
  // Also optionally record history if table exists
  try {
    await pool.query(
      `INSERT INTO system_health_history(service_key, status, latency_ms, message, checked_at)
       VALUES ($1,$2,$3,$4, NOW())`,
      [service_key, status, latency_ms ?? null, message ?? null]
    );
  } catch (_) { /* history table optional */ }
}

async function checkDb() {
  const start = Date.now();
  try {
    await pool.query('SELECT 1');
    const ms = Date.now() - start;
    return { status: mapByLatency(true, ms), latency: ms, message: 'OK' };
  } catch (e) {
    return { status: 'down', latency: null, message: e.message };
  }
}

async function checkMeterApi() {
  const start = Date.now();
  try {
    const res = await timeoutFetch(meterApiHealthUrl, HEALTH_DEFAULT_TIMEOUT_MS);
    const ms = Date.now() - start;
    return { status: mapByLatency(res.ok, ms), latency: ms, message: `HTTP ${res.status}` };
  } catch (e) {
    return { status: 'down', latency: null, message: e.message };
  }
}

// Ensure heartbeat table exists
async function ensureJobsHeartbeatTable() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS jobs_heartbeat (
      id smallint PRIMARY KEY DEFAULT 1,
      last_beat timestamptz NOT NULL DEFAULT NOW()
    );`);
    await pool.query(`INSERT INTO jobs_heartbeat (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`);
  } catch (_) {}
}

async function updateJobsHeartbeat() {
  await ensureJobsHeartbeatTable();
  await pool.query('UPDATE jobs_heartbeat SET last_beat = NOW() WHERE id = 1');
}

async function checkJobs() {
  await ensureJobsHeartbeatTable();
  try {
    const { rows } = await pool.query('SELECT last_beat FROM jobs_heartbeat WHERE id = 1');
    if (!rows.length) return { status: 'unknown', latency: null, message: 'No heartbeat' };
    const last = new Date(rows[0].last_beat).getTime();
    const now = Date.now();
    const diffMs = now - last;
    let status = 'down';
    if (diffMs < 2 * 60 * 1000) status = 'healthy';
    else if (diffMs < 10 * 60 * 1000) status = 'degraded';
    else status = 'down';
    return { status, latency: diffMs, message: `last beat ${Math.round(diffMs/1000)}s ago` };
  } catch (e) {
    return { status: 'down', latency: null, message: e.message };
  }
}

async function checkMail() {
  const nodemailer = require('nodemailer');
  if (!process.env.SMTP_HOST) return { status: 'unknown', latency: null, message: 'SMTP not configured' };
  const start = Date.now();
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: (process.env.SMTP_USER && process.env.SMTP_PASS) ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
      connectionTimeout: HEALTH_DEFAULT_TIMEOUT_MS,
      greetingTimeout: HEALTH_DEFAULT_TIMEOUT_MS,
      socketTimeout: HEALTH_DEFAULT_TIMEOUT_MS
    });
    await transporter.verify();
    const ms = Date.now() - start;
    return { status: mapByLatency(true, ms), latency: ms, message: 'SMTP OK' };
  } catch (e) {
    return { status: 'down', latency: null, message: e.message };
  }
}

function buildSmtpTransporter() {
  const nodemailer = require('nodemailer');
  if (!process.env.SMTP_HOST) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: (process.env.SMTP_USER && process.env.SMTP_PASS) ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
    connectionTimeout: HEALTH_DEFAULT_TIMEOUT_MS,
    greetingTimeout: HEALTH_DEFAULT_TIMEOUT_MS,
    socketTimeout: HEALTH_DEFAULT_TIMEOUT_MS
  });
}

async function runAllHealthChecks() {
  const results = await Promise.allSettled([
    checkDb().then(r => ({ key: 'db', ...r })),
    checkDisk().then(r => ({ key: 'disk', ...r })),
    checkProcess().then(r => ({ key: 'process', ...r })),
    checkClock().then(r => ({ key: 'clock', ...r })),
    checkTlsCert().then(r => ({ key: 'tls_cert', ...r })),
  ]);
  for (const r of results) {
    if (r.status === 'fulfilled') {
      const { key, status, latency, message } = r.value;
      await upsertHealth(key, status, latency, message);
    }
  }
}

// Kick off scheduler (every 5 minutes)
setInterval(() => { runAllHealthChecks().catch(() => {}); }, 5 * 60 * 1000);
// Do an initial run shortly after boot
setTimeout(() => { runAllHealthChecks().catch(() => {}); }, 3000);

// Expose an endpoint your scheduler (or a simple cron) can call to update heartbeat
app.post('/api/jobs/heartbeat', requireStaff, async (req, res) => {
  try {
    await updateJobsHeartbeat();
    res.json({ status: 'success' });
  } catch (e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// --- ADDED --- (Step 3: Create middleware to load settings for Admin pages)
const loadCompanySettings = async (req, res, next) => {
    // We attach settings to res.locals, which are automatically available in EJS templates
    res.locals.companyLogoUrl = null; // Set a default
    let client;
    try {
        client = await pool.connect();
        // Fetch the logo_url from the company_settings table
        const result = await client.query("SELECT logo_url FROM company_settings WHERE id = 1");
        
        if (result.rows.length > 0) {
            // If we find a logo, make it available to the EJS template
            res.locals.companyLogoUrl = result.rows[0].logo_url;
        }
    } catch (err) {
        // Log the error but don't block the request
        console.error("Failed to load company settings for sidebar:", err);
    } finally {
        if (client) {
            client.release();
        }
    }
    // Continue to the next middleware (requireAdmin) or the route handler
    next();
};


// Shared demo invoices data (used by /billing and /receipt)
const invoicesData = [
    { 
        id: 'INV-00125', issueDate: '2025-10-05', dueDate: '2025-10-25', amount: '465.50', status: 'Due',
        customerName: 'Customer User Demo',
        address: '1234 Olaya St, Al-Sulimaniah, Riyadh 12245',
        accountNumber: '45891000000',
        meterNumber: '10110071690',
        billingUnits: 'm³',
        meterDiameter: '19',
        consumptionStartDate: '2024-09-05',
        startRead: '17658.11',
        consumptionEndDate: '2024-10-05',
        endRead: '17862.62',
        beforeVAT: '750.02',
        vatPercentage: '15%',
        vatValue: '112.50',
        afterVAT: '862.52',
        consumptionValue: '750.02',
        serviceFee: '375.01',
        meterTariff: '5.00',
        totalAmount: '1299.53'
    },
    { 
        id: 'INV-00124', issueDate: '2025-09-05', dueDate: '2025-09-25', amount: '450.00', status: 'Paid',
        customerName: 'Customer User Demo',
        address: '1234 Olaya St, Al-Sulimaniah, Riyadh 12245',
        accountNumber: '987-654-3210',
        meterNumber: '65315101',
        billingUnits: 'm³',
        meterDiameter: '2 inches',
        consumptionStartDate: '2025-08-03',
        startRead: '11195',
        consumptionEndDate: '2025-09-02',
        endRead: '12345',
        beforeVAT: '391.30',
        vatPercentage: '15%',
        vatValue: '58.70',
        afterVAT: '450.00',
        consumptionValue: '380.00',
        serviceFee: '5.30',
        meterTariff: '6.00',
        totalAmount: '450.00'
    },
    { 
        id: 'INV-00123', issueDate: '2025-08-05', dueDate: '2025-08-25', amount: '435.50', status: 'Paid',
        customerName: 'Customer User Demo',
        address: '1234 Olaya St, Al-Sulimaniah, Riyadh 12245',
        accountNumber: '987-654-3210',
        meterNumber: '65315102',
        billingUnits: 'm³',
        meterDiameter: '2 inches',
        consumptionStartDate: '2025-07-03',
        startRead: '10000',
        consumptionEndDate: '2025-08-02',
        endRead: '10500',
        beforeVAT: '378.26',
        vatPercentage: '15%',
        vatValue: '56.79',
        afterVAT: '435.05',
        consumptionValue: '378.26',
        serviceFee: '4.00',
        meterTariff: '5.00',
        totalAmount: '435.50'
    }
];


// --- UPDATED ROUTES ---

// UPDATED: Root route now redirects based on the user's role if a session exists
app.get('/', (req, res) => {
  if (req.session.user) {
    if (['admin', 'operator', 'superadmin'].includes(req.session.user.role)) {
      return res.redirect('/admin/home');
    }
    return res.redirect('/home');
  }
  res.render('Customer/login', { error: null });
});


// UPDATED: Login route now assigns roles and redirects
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // 1) Staff login (admin/operator)
    const { rows } = await pool.query('SELECT id, username, password_hash, role, is_active FROM staff_users WHERE username=$1 LIMIT 1', [username]);
    if (rows.length && rows[0].is_active !== false) {
      const u = rows[0];
      const ok = await bcrypt.compare(password, u.password_hash);
      if (ok) {
        const sessionRole = (u.role === 'master') ? 'admin' : 'operator';
        req.session.user = { name: u.username, uid: u.id, role: sessionRole };
        return res.redirect('/admin/home');
      }
    }

    // 2) Customer login (signup accounts)
    const { rows: customerRows } = await pool.query(
      `SELECT ca.id, ca.username, ca.password_hash, ca.company_id, c.company_name
       FROM customer_accounts ca
       JOIN companies c ON c.id = ca.company_id
       WHERE ca.username=$1
       LIMIT 1`,
      [username]
    );

    if (customerRows.length) {
      const cu = customerRows[0];
      const ok = await bcrypt.compare(password, cu.password_hash);
      if (ok) {
        req.session.user = { name: cu.username, uid: cu.id, role: 'customer', companyId: cu.company_id };
        // Update last_activity_at for Control Center visibility
        await pool.query('UPDATE companies SET last_activity_at = NOW() WHERE id=$1', [cu.company_id]);
        return res.redirect('/home');
      }
    }
  } catch (err) {
    console.error('Login error:', err);
  }

  // Super Admin fallback login (not visible in UI)
  if (username === 'admin_demo' && password === 'Demo@123') {
    req.session.user = { name: 'Super Admin', uid: 0, role: 'superadmin' };
    return res.redirect('/admin/home');
  }

  // Optional demo customer login retained
  if (username === 'customer_demo' && password === 'Demo@123') {
    req.session.user = { name: 'Customer User Demo', uid: 1, role: 'customer' };
    return res.redirect('/home');
  }

  return res.render('Customer/login', { error: 'Invalid username or password. Please try again.' });
});

// Signup routes for creating a new demo account
app.get('/signup', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('Customer/signup', { error: null });
});

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || username.trim().length < 3 || password.length < 6) {
    return res.status(400).render('Customer/signup', { error: 'Username must be at least 3 characters and password at least 6 characters.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const cleanUsername = username.trim();

    // Ensure username is unique among staff users
    const existingStaff = await client.query('SELECT 1 FROM staff_users WHERE username=$1', [cleanUsername]);
    if (existingStaff.rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).render('Customer/signup', { error: 'This admin username is already taken. Please choose another.' });
    }

    const companyName = `DEMO (${cleanUsername})`;

    // Create company for this demo admin account
    const companyResult = await client.query(
      `INSERT INTO companies (company_name, status, date_registered, last_activity_at)
       VALUES ($1, 'Active', NOW(), NOW())
       RETURNING id`,
      [companyName]
    );
    const companyId = companyResult.rows[0].id;

    // Attach Demo plan if it exists
    const planResult = await client.query('SELECT id FROM subscription_plans WHERE plan_name=$1 LIMIT 1', ['Demo']);
    if (planResult.rows.length) {
      const planId = planResult.rows[0].id;
      const licenseCode = `DEMO-${companyId}`;
      await client.query(
        `INSERT INTO company_licenses (company_id, license_code, plan_id, start_date, expiry_date, is_paid)
         VALUES ($1,$2,$3,CURRENT_DATE, CURRENT_DATE + INTERVAL '30 days', FALSE)`,
        [companyId, licenseCode, planId]
      );
    }

    // Create staff admin account with hashed password
    const hash = await bcrypt.hash(password, 12);
    const staffResult = await client.query(
      `INSERT INTO staff_users (username, password_hash, role, is_active)
       VALUES ($1, $2, 'master', true)
       RETURNING id`,
      [cleanUsername, hash]
    );

    await client.query('COMMIT');

    // Auto-login the user as admin and redirect to admin home
    req.session.user = { name: cleanUsername, uid: staffResult.rows[0].id, role: 'admin' };
    return res.redirect('/admin/home');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Signup failed:', e);
    // If the database reports a unique violation (e.g. username already exists),
    // surface a clear message instead of a generic error.
    if (e && e.code === '23505') {
      return res.status(409).render('Customer/signup', { error: 'This admin username is already taken. Please choose another.' });
    }
    return res.status(500).render('Customer/signup', { error: 'Failed to create your account. Please try again later.' });
  } finally {
    client.release();
  }
});

// Logout Route - works for both roles
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/');
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// --- REVA LITEBILL ROUTES ---
const liteBillRoutes = require('./backend.js');
app.use('/', liteBillRoutes);

//---------------------------------------------------------------------------------------//
app.use('/admin', loadCompanySettings, requireStaff);

// --- NEW: Admin Routes ---
// All routes for the admin panel should be placed here and use `requireAdmin`

app.get('/admin/home', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/home_ad', {
        user: req.session.user,
        activePage: 'home'
    });
});


app.get('/admin/customer_management', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/customer_management', {
        user: req.session.user,
        activePage: 'customer_management'
    });
});

app.get('/admin/meter_management', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/meter_management', {
        user: req.session.user,
        activePage: 'meter_management'
    });
});

app.get('/admin/billing_finance', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/billing_finance', {
        user: req.session.user,
        activePage: 'billing_finance'
    });
});

app.get('/admin/analytics_reports', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/analytics_reports', {
        user: req.session.user,
        activePage: 'analytics_reports'
    });
});

app.get('/admin/dashboards', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/dashboards', {
        user: req.session.user,
        activePage: 'dashboards'
    });
});

app.get('/admin/settings', requireStaff, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT id, username, role, is_active FROM staff_users ORDER BY role');
        res.render('Admin/settings', {
            user: req.session.user,
            activePage: 'settings',
            staffUsers: rows,
            currentTab: req.query.tab || null
        });
    } catch (e) {
        console.error('Error loading staff users for settings:', e);
        res.render('Admin/settings', {
            user: req.session.user,
            activePage: 'settings',
            staffUsers: [],
            currentTab: req.query.tab || null
        });
    }
});

app.get('/admin/support_center', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/support_center', {
        user: req.session.user,
        activePage: 'support_center'
    });
});

app.get('/admin/reva_lite_bill', requireStaff, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/reva_lite_bill', {
        user: req.session.user,
        activePage: 'reva_lite_bill'
    });
});

//---------------------------------------------------------------------------------------//

   



// --- Super Admin: Control Center ---
app.get('/admin/control-center', requireSuperAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.company_name, c.status, c.last_activity_at,
             sp.plan_name, sp.max_customers,
             si.platform_version
      FROM companies c
      LEFT JOIN company_licenses cl ON cl.company_id = c.id
      LEFT JOIN subscription_plans sp ON sp.id = cl.plan_id
      LEFT JOIN system_instances si ON si.company_id = c.id
      ORDER BY c.company_name ASC`);
    res.render('Admin/control_center', { user: req.session.user, activePage: 'control_center', companies: rows });
  } catch (e) {
    console.error('Control Center list failed:', e);
    res.status(500).send('Failed to load Control Center');
  }
});

app.get('/admin/control-center/company/:id', requireSuperAdmin, async (req, res) => {
  const companyId = Number(req.params.id);
  try {
    const [c, lic, plans, inst] = await Promise.all([
      pool.query('SELECT * FROM companies WHERE id=$1 LIMIT 1', [companyId]),
      pool.query(`SELECT cl.*, sp.plan_name, sp.max_data_transfer_gb FROM company_licenses cl LEFT JOIN subscription_plans sp ON sp.id = cl.plan_id WHERE company_id=$1 LIMIT 1`, [companyId]),
      pool.query('SELECT id, plan_name, max_data_transfer_gb FROM subscription_plans ORDER BY id'),
      pool.query('SELECT * FROM system_instances WHERE company_id=$1 LIMIT 1', [companyId])
    ]);
    if (!c.rows.length) return res.status(404).send('Company not found');
    res.render('Admin/company_detail', {
      user: req.session.user,
      activePage: 'control_center',
      company: c.rows[0],
      license: lic.rows[0] || null,
      plans: plans.rows,
      instance: inst.rows[0] || null
    });
  } catch (e) {
    console.error('Company detail failed:', e);
    res.status(500).send('Failed to load Company');
  }
});

app.post('/admin/control-center/company/:id', requireSuperAdmin, async (req, res) => {
  const companyId = Number(req.params.id);
  const { company_name, reva_platform_id, address, contact_email, phone, status } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const before = await client.query('SELECT company_name, reva_platform_id, address, contact_email, phone, status FROM companies WHERE id=$1', [companyId]);
    await client.query(`UPDATE companies SET company_name=$1, reva_platform_id=$2, address=$3, contact_email=$4, phone=$5, status=$6 WHERE id=$7`,
      [company_name, reva_platform_id || null, address || null, contact_email || null, phone || null, status, companyId]);
    const details = `Company updated from ${JSON.stringify(before.rows[0] || {})} to ${JSON.stringify({ company_name, reva_platform_id, address, contact_email, phone, status })}`;
    await client.query(`INSERT INTO admin_audit_logs (admin_user_id, company_id, action_type, details) VALUES ($1,$2,'COMPANY_UPDATE',$3)`,
      [req.session.user.uid, companyId, details]);
    await client.query('COMMIT');
    res.redirect(`/admin/control-center/company/${companyId}`);
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Company update failed:', e);
    res.status(500).send('Failed to update company');
  } finally {
    client.release();
  }
});

app.post('/admin/control-center/company/:id/license', requireSuperAdmin, async (req, res) => {
  const companyId = Number(req.params.id);
  const { license_code, udo_reference_string, plan_id, start_date, expiry_date, is_paid } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query('SELECT id FROM company_licenses WHERE company_id=$1 LIMIT 1', [companyId]);
    if (rows.length) {
      await client.query(`UPDATE company_licenses SET license_code=$1, udo_reference_string=$2, plan_id=$3, start_date=$4, expiry_date=$5, is_paid=$6 WHERE company_id=$7`,
        [license_code, udo_reference_string || null, plan_id || null, start_date, expiry_date, String(is_paid) === 'true', companyId]);
    } else {
      await client.query(`INSERT INTO company_licenses (company_id, license_code, udo_reference_string, plan_id, start_date, expiry_date, is_paid) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [companyId, license_code, udo_reference_string || null, plan_id || null, start_date, expiry_date, String(is_paid) === 'true']);
    }
    await client.query(`INSERT INTO admin_audit_logs (admin_user_id, company_id, action_type, details) VALUES ($1,$2,'LICENSE_UPDATE',$3)`,
      [req.session.user.uid, companyId, `License updated: code=${license_code}, plan_id=${plan_id}, paid=${String(is_paid) === 'true'}`]);
    await client.query('COMMIT');
    res.redirect(`/admin/control-center/company/${companyId}`);
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('License update failed:', e);
    res.status(500).send('Failed to update license');
  } finally {
    client.release();
  }
});

app.post('/admin/control-center/company/:id/suspend', requireSuperAdmin, async (req, res) => {
  const companyId = Number(req.params.id);
  const { message } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE companies SET status='Suspended', suspension_message=$2 WHERE id=$1`, [companyId, message || null]);
    await client.query(`INSERT INTO admin_audit_logs (admin_user_id, company_id, action_type, details) VALUES ($1,$2,'ACCOUNT_SUSPEND',$3)`,
      [req.session.user.uid, companyId, message ? `Suspended with message: ${message}` : 'Suspended']);
    await client.query('COMMIT');
    res.redirect(`/admin/control-center/company/${companyId}`);
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Account suspend failed:', e);
    res.status(500).send('Failed to suspend account');
  } finally {
    client.release();
  }
});

app.post('/admin/control-center/company/:id/activate', requireSuperAdmin, async (req, res) => {
  const companyId = Number(req.params.id);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE companies SET status='Active' WHERE id=$1`, [companyId]);
    await client.query(`INSERT INTO admin_audit_logs (admin_user_id, company_id, action_type, details) VALUES ($1,$2,'ACCOUNT_ACTIVATE',$3)`,
      [req.session.user.uid, companyId, 'Activated account']);
    await client.query('COMMIT');
    res.redirect(`/admin/control-center/company/${companyId}`);
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Account activate failed:', e);
    res.status(500).send('Failed to activate account');
  } finally {
    client.release();
  }
});

// --- System Health API ---
app.get('/api/system-health', requireStaff, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT service_key, status, latency_ms, message, checked_at FROM system_health ORDER BY service_key');
    res.json({ status: 'success', data: rows });
  } catch (e) {
    console.error('Fetch system-health failed:', e);
    res.status(500).json({ status: 'error', message: 'Failed to fetch system health' });
  }
});

app.post('/api/system-health/refresh', requireStaff, async (req, res) => {
  try {
    await runAllHealthChecks();
    const { rows } = await pool.query('SELECT service_key, status, latency_ms, message, checked_at FROM system_health ORDER BY service_key');
    res.json({ status: 'success', data: rows });
  } catch (e) {
    console.error('Refresh system-health failed:', e);
    res.status(500).json({ status: 'error', message: 'Failed to refresh system health' });
  }
});

   
   



// --- PROTECTED Customer Routes ---
// --- Admin: Users & Permissions ---
app.get('/admin/users', requireMaster, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT id, username, role, is_active, created_at, updated_at FROM staff_users ORDER BY role');
        res.render('Admin/users_manage', { user: req.session.user, activePage: 'users', users: rows });
    } catch (e) {
        console.error('Error loading staff users:', e);
        res.status(500).send('Failed to load users');
    }
});

app.post('/admin/users/:role', requireMaster, async (req, res) => {
    const role = req.params.role;
    if (!['master', 'operator'].includes(role)) return res.status(400).send('Invalid role');
    const { username, password } = req.body;
    if (!username || username.trim().length < 3) return res.status(400).send('Invalid username');
    try {
        if (password && password.trim()) {
            const hash = await bcrypt.hash(password.trim(), 12);
            await pool.query('UPDATE staff_users SET username=$1, password_hash=$2, updated_at=NOW() WHERE role=$3', [username.trim(), hash, role]);
        } else {
            await pool.query('UPDATE staff_users SET username=$1, updated_at=NOW() WHERE role=$2', [username.trim(), role]);
        }
        res.redirect('/admin/settings?tab=roles');
    } catch (e) {
        console.error('Update staff user failed:', e);
        res.status(500).send('Failed to update user');
    }
});
// All customer routes now use `requireCustomer` for protection

// Home Page Route - Odoo references removed
// Home Page Route
// Home Page Route
app.get('/home', requireCustomer, (req, res) => {
    // In a real app, you would fetch this summary data from your database
    const kpiData = {
        currentBalance: '125.50',
        nextBillDue: '130.00',
        lastPaidDate: 'December 15, 2025',
        nextBillDate: 'January 20, 2026'
    };

    const usageGraphData = {
        labels: ['Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        values: [4200, 4500, 4300, 4600, 4400, 4750]
    };

    const recentTransactions = [
        { date: '2025-12-15', description: 'Payment Received', amount: '-125.50' },
        { date: '2025-11-20', description: 'Monthly Bill', amount: '130.00' },
        { date: '2025-10-20', description: 'Monthly Bill', amount: '115.00' }
    ];

    // Prepare a meaningful initial live reading (simulate using masterMeterData if available)
    const defaultMeter = masterMeterData && masterMeterData.length ? masterMeterData[0] : null;
    const parseNumber = (s) => {
        if (!s) return 0;
        return Number(String(s).replace(/[^0-9.-]+/g, '')) || 0;
    };
    const baseReading = defaultMeter ? parseNumber(defaultMeter.lastReading) : 12345;
    const initialReadingValue = baseReading + Math.floor(Math.random() * 10); // small increment
    const formatNumber = (n) => n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    const initialReading = formatNumber(initialReadingValue);
    const initialTimestamp = new Date().toLocaleString('en-US', { month: 'long', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });

    res.render('Customer/home', {
        user: req.session.user,
        activePage: 'home',
        kpis: kpiData,
        graphData: usageGraphData,
        transactions: recentTransactions,
        initialReading: initialReading,
        initialUnit: defaultMeter && defaultMeter.lastReading && String(defaultMeter.lastReading).includes('gal') ? 'gal' : (defaultMeter && defaultMeter.billingUnits) || 'units',
        initialTimestamp: initialTimestamp
    });
});

// API endpoint to return a simulated live reading (for the Refresh button)
app.get('/api/reading', requireCustomer, (req, res) => {
    const defaultMeter = masterMeterData && masterMeterData.length ? masterMeterData[0] : null;
    const parseNumber = (s) => {
        if (!s) return 0;
        return Number(String(s).replace(/[^0-9.-]+/g, '')) || 0;
    };
    const baseReading = defaultMeter ? parseNumber(defaultMeter.lastReading) : 12345;
    // Simulate a realistic current reading and small random variance
    const readingValue = baseReading + Math.floor(Math.random() * 25);
    const formatNumber = (n) => n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    const readingStr = formatNumber(readingValue);
    const timestamp = new Date();
    const formatted = timestamp.toLocaleString('en-US', { month: 'long', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });

    res.json({ reading: readingStr, unit: defaultMeter && defaultMeter.lastReading && String(defaultMeter.lastReading).includes('gal') ? 'gal' : (defaultMeter && defaultMeter.billingUnits) || 'units', timestamp: timestamp.toISOString(), formatted });
});


// Billing Page Route
app.get('/billing', requireCustomer, (req, res) => {
    // Use shared invoicesData
    const paymentHistoryData = [
        { id: 'TXN-98765', date: '2025-09-20', description: `Payment for ${invoicesData[1].id}`, amount: `SAR ${invoicesData[1].totalAmount}`, method: 'Mada', receiptUrl: `/receipt/${invoicesData[1].id}` },
        { id: 'TXN-98764', date: '2025-08-19', description: `Payment for ${invoicesData[2].id}`, amount: `SAR ${invoicesData[2].totalAmount}`, method: 'Visa', receiptUrl: `/receipt/${invoicesData[2].id}` }
    ];

    const planDetails = {
        type: 'Postpaid Residential',
        totalDue: '465.50',
        rates: [
            { tier: '1 - 15 m³', rate: '0.10' }, { tier: '16 - 30 m³', rate: '1.00' },
            { tier: '31 - 45 m³', rate: '3.00' }, { tier: '46 - 60 m³', rate: '4.00' },
            { tier: '> 60 m³', rate: '6.00' }
        ]
    };

    res.render('Customer/billing', { 
        user: req.session.user, 
        activePage: 'billing',
        invoices: invoicesData,
        paymentHistory: paymentHistoryData,
        plan: planDetails
    });
});

// Reports Page Route
// Reports Page Route
// Reports Page Route
app.get('/reports', requireCustomer, (req, res) => {
    // In a real app, you would fetch this from the database
    const metersList = masterMeterData.map(m => ({ id: m.id, location: m.location }));

    // UPDATED: Set the downloadUrl to the receipt generation route /receipt/:invoiceId
    const pastInvoices = [
        { id: 'INV-00124', issueDate: '2025-09-05', amount: 'SAR 450.00', status: 'Paid', downloadUrl: `/receipt/INV-00124` },
        { id: 'INV-00123', issueDate: '2025-08-05', amount: 'SAR 435.50', status: 'Paid', downloadUrl: `/receipt/INV-00123` },
        { id: 'INV-00122', issueDate: '2025-07-05', amount: 'SAR 445.00', status: 'Paid', downloadUrl: `/receipt/INV-00122` },
        { id: 'INV-00121', issueDate: '2025-06-05', amount: 'SAR 420.75', status: 'Paid', downloadUrl: `/receipt/INV-00121` }
    ];

    res.render('Customer/reports', { 
        user: req.session.user, 
        activePage: 'reports',
        meters: metersList,
        invoices: pastInvoices
    });
});

// Settings Page Route
app.get('/settings', requireCustomer, (req, res) => {
    const paymentMethods = [
        { id: 1, type: 'Visa', details: 'ending in 1234', expiry: '08/2026', isDefault: true },
        { id: 2, type: 'Bank Account', details: 'ending in 5678', accountType: 'Checking Account', isDefault: false }
    ];
    res.render('Customer/settings', { user: req.session.user, activePage: 'settings', paymentMethods: paymentMethods });
});

// Meters Page Route
app.get('/meters', requireCustomer, (req, res) => {
    const { status } = req.query;
    let filteredMeters = masterMeterData;
    if (status) {
        filteredMeters = masterMeterData.filter(meter => meter.status === status);
    }
    res.render('Customer/meters', {
        user: req.session.user,
        activePage: 'meters',
        meters: filteredMeters,
        activeFilter: status || 'All Meters'
    });
});

// Usage Details Page Route
app.get('/usage-details', requireCustomer, (req, res) => {
    // In a real application, you would fetch this data from your database
    const usageChartData = {
        weekly: {
            labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            values: [1150, 1200, 1100, 1180]
        },
        monthly: {
            labels: ['July', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            values: [4500, 4200, 4600, 4400, 4700, 4800]
        },
        yearly: {
            labels: ['2023', '2024', '2025'],
            values: [55000, 59000, 61000]
        }
    };

    res.render('Customer/usage-details', {
        user: req.session.user,
        activePage: 'usage-details',
        chartData: usageChartData
    });
});

// Alerts & Notifications Page Route
app.get('/alerts', requireCustomer, (req, res) => {
    // In a real app, this data would come from a database or a real-time events system
    const alertsData = [
        {
            type: 'overdue',
            title: 'Overdue Bill Alert',
            timestamp: 'October 2, 2025',
            message: 'Your bill for invoice INV-00124 (SAR 450.00) is now 7 days overdue. Please make a payment to avoid service disruption.',
            link: '/billing',
            linkText: 'Pay Now'
        },
        {
            type: 'usage',
            title: 'Abnormal Usage Detected',
            timestamp: 'September 30, 2025',
            message: 'We detected continuous water flow at meter SA-RYD-004 for over 6 hours, which may indicate a leak. We recommend checking your property for potential issues.',
            link: '/meters',
            linkText: 'View Meter Details'
        },
        {
            type: 'service',
            title: 'Planned Service Interruption',
            timestamp: 'September 28, 2025',
            message: 'Please be advised of a planned service interruption in the Olaya District for system maintenance on October 10, 2025, from 1:00 AM to 5:00 AM.',
        }
    ];

    // Calculate KPIs
    const kpiData = {
        total: alertsData.length,
        urgent: alertsData.filter(a => a.type === 'overdue' || a.type === 'usage').length,
        info: alertsData.filter(a => a.type === 'service').length
    };

    res.render('Customer/alerts', {
        user: req.session.user,
        activePage: 'alerts',
        alerts: alertsData,
        kpis: kpiData // Pass KPI data to the page
    });
});

// Support & Help Page Route
app.get('/support', requireCustomer, (req, res) => {
    // In a real app, you would fetch FAQs from a database or CMS
    const faqData = [
        {
            question: 'How is my water bill calculated?',
            answer: 'Your water bill is calculated based on a tiered system known as block rates. The price per cubic meter increases as your consumption moves into higher tiers. You can view the specific rates for your plan on the Billing & Payments page.'
        },
        {
            question: 'What should I do if I suspect a water leak?',
            answer: 'If you suspect a leak, first check your property for any visible signs like dripping faucets or wet spots. You can also monitor your meter for continuous activity. If you confirm a leak or see an abnormal usage alert, we recommend contacting a certified plumber immediately.'
        },
        {
            question: 'How can I update my payment information?',
            answer: 'You can manage your payment methods on the Settings page. From there, you can add a new credit/debit card or bank account, set a default payment method, and remove old ones.'
        }
    ];

    res.render('Customer/support', {
        user: req.session.user,
        activePage: 'support',
        faqs: faqData
    });
});

// --- Data and Server Setup ---

const masterMeterData = [
    {
        id: 'SA-RYD-001',
        meterNumber: '65315101',
        billNumber: '294511223344',
        releaseDate: '2025-09-05',
        deadlineDate: '2025-09-25',
        periodStartDate: '2025-08-03',
        periodEndDate: '2025-09-02',
        periodStartReading: 11195,
        periodEndReading: 12345,
        status: 'Active',
        lastReading: '12,345 gal',
        totalReadings: '150,500 gal',
        location: 'Olaya District, Riyadh',
        buildingType: 'Commercial Building',
        amount: 'SAR 450.00',
        previousBillAmount: 0,
        lat: 24.7011,
        lng: 46.6835,
        paymentHistory: [
            { date: '2025-09-20', description: 'Monthly Bill', amount: '- SAR 450.00', status: 'Paid', type: 'Debit' },
            { date: '2025-08-20', description: 'Monthly Bill', amount: '- SAR 435.50', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-002',
        meterNumber: '65315102',
        billNumber: '294522334455',
        releaseDate: '2025-09-01',
        deadlineDate: '2025-09-20',
        periodStartDate: '2025-07-29',
        periodEndDate: '2025-08-28',
        periodStartReading: null,
        periodEndReading: null,
        status: 'Inactive',
        lastReading: 'N/A',
        totalReadings: '89,000 gal',
        location: 'Al Malaz, Riyadh',
        buildingType: 'Residential Building',
        amount: 'SAR 210.50',
        previousBillAmount: 0,
        lat: 24.6633,
        lng: 46.7381,
        paymentHistory: [
            { date: '2025-09-15', description: 'Final Bill', amount: '- SAR 210.50', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-003',
        meterNumber: '65315103',
        billNumber: '294533445566',
        releaseDate: '2025-09-10',
        deadlineDate: '2025-10-10',
        periodStartDate: '2025-06-09',
        periodEndDate: '2025-09-08',
        periodStartReading: 60890,
        periodEndReading: 67890,
        status: 'Active',
        lastReading: '67,890 gal',
        totalReadings: '750,000 gal',
        location: 'Diplomatic Quarter, Riyadh',
        buildingType: 'Government Building',
        amount: 'SAR 2,150.00',
        previousBillAmount: 0,
        lat: 24.6853,
        lng: 46.6325,
        paymentHistory: [
            { date: '2025-09-25', description: 'Quarterly Bill', amount: '- SAR 2,150.00', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-004',
        meterNumber: '65315104',
        billNumber: '294544556677',
        releaseDate: '2025-09-02',
        deadlineDate: '2025-09-22',
        periodStartDate: '2025-07-31',
        periodEndDate: '2025-08-30',
        periodStartReading: 48821,
        periodEndReading: 54321,
        status: 'Needs Attention',
        lastReading: '54,321 gal',
        totalReadings: '432,100 gal',
        location: 'King Abdullah Financial District, Riyadh',
        buildingType: 'Commercial Building',
        amount: 'SAR 1,812.20',
        previousBillAmount: 0,
        lat: 24.7631,
        lng: 46.6433,
        paymentHistory: [
             { date: '2025-09-18', description: 'Payment Attempt', amount: '- SAR 1,812.20', status: 'Failed', type: 'Debit' },
             { date: '2025-08-18', description: 'Monthly Bill', amount: '- SAR 1,750.00', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-005',
        meterNumber: '65315105',
        billNumber: '294555667788',
        releaseDate: '2025-09-07',
        deadlineDate: '2025-09-27',
        periodStartDate: '2025-08-06',
        periodEndDate: '2025-09-05',
        periodStartReading: 88765,
        periodEndReading: 98765,
        status: 'Active',
        lastReading: '98,765 gal',
        totalReadings: '995,400 gal',
        location: 'Al-Naseem, Riyadh',
        buildingType: 'Residential Building',
        amount: 'SAR 3,100.75',
        previousBillAmount: 0,
        lat: 24.7241,
        lng: 46.8229,
        paymentHistory: [
            { date: '2025-09-22', description: 'Monthly Bill', amount: '- SAR 3,100.75', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-006',
        meterNumber: '65315106',
        billNumber: '294566778899',
        releaseDate: '2025-09-12',
        deadlineDate: '2025-10-02',
        periodStartDate: '2025-08-11',
        periodEndDate: '2025-09-10',
        periodStartReading: 3567,
        periodEndReading: 4567,
        status: 'Active',
        lastReading: '4,567 gal',
        totalReadings: '210,800 gal',
        location: 'Al-Sulimaniah, Riyadh',
        buildingType: 'Residential Building',
        amount: 'SAR 385.50',
        previousBillAmount: 0,
        lat: 24.7050,
        lng: 46.7000,
        paymentHistory: [
            { date: '2025-09-28', description: 'Monthly Bill', amount: '- SAR 385.50', status: 'Paid', type: 'Debit' },
            { date: '2025-08-28', description: 'Monthly Bill', amount: '- SAR 370.00', status: 'Paid', type: 'Debit' }
        ]
    }
];

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.on('connection', (socket) => {
  console.log('A user connected with ID:', socket.id);
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

server.listen(port, () => {
  console.log(`✅ Server is running on http://localhost:${port}`);
});

// Remove the imports: const PDFDocument = require('pdfkit'); and const fs = require('fs');
// ...

// Route to generate and download invoice receipt PDF
app.get('/receipt/:invoiceId', async (req, res) => {
    const invoiceId = req.params.invoiceId;
    
    // 1. Fetch Invoice Data (Source of the 'invoice' variable)
    const invoice = invoicesData.find(inv => inv.id === invoiceId);
    
    if (!invoice || invoice.status !== 'Paid') {
        return res.status(404).send('Paid Invoice details not found.');
    }
    
    // 2. Calculate EJS Variables
    const waterBefore = Number(invoice.consumptionValue || 0);
    const sewerBefore = Number(invoice.serviceFee || 0);
    const tariffBefore = Number(invoice.meterTariff || 0);
    const consumption = (Number(invoice.endRead) - Number(invoice.startRead)).toFixed(2);
    
    const totalBefore = (waterBefore + sewerBefore + tariffBefore).toFixed(2);
    const totalVAT = (Number(waterBefore * 0.15) + Number(sewerBefore * 0.15) + Number(tariffBefore * 0.15)).toFixed(2);
    const totalAfter = Number(invoice.totalAmount).toFixed(2); 

    try {
        // 3. Render EJS to HTML String - POINTING TO CORRECT FILE: receipt.ejs
        const filePath = path.join(__dirname, 'views', 'Customer', 'partials','receipt.ejs'); // <-- CONFIRMED PATH
        
        const htmlContent = await ejs.renderFile(filePath, { 
            invoice: invoice, // <-- This defines the 'invoice' variable for EJS
            consumption: consumption,
            totalBefore: totalBefore,
            totalVAT: totalVAT,
            totalAfter: totalAfter
        });

        // NEW (FIXED) CODE:
        const browser = await puppeteer.launch({ headless: true });
        const page = await browser.newPage();
        
        // Load the HTML content
        await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
        
        // 5. Generate PDF
        const pdfBuffer = await page.pdf({ 
            format: 'A4', 
            printBackground: true, 
            margin: {
                top: '0.2in',
                right: '0.2in',
                bottom: '0.2in',
                left: '0.2in'
            }
        });

        await browser.close();

        // 6. Send PDF as a Download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Water_Bill_Receipt_${invoiceId}.pdf`);
        res.send(pdfBuffer);

    } catch (error) {
        // Log the error and display the friendly message
        console.error('Puppeteer/PDF Generation Failed:', error.message);
        res.status(500).send('Error generating downloadable PDF.');
    }
});


app.get('/reports/generate', requireCustomer, async (req, res) => {
    const { report_type, startDate, endDate, meterId, format } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).send('Start Date and End Date are required.');
    }
    
    // Helper function to format date to YYYY-MM-DD reliably, avoiding UTC/ISO issues
    const formatDate = (date) => {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0'); // Month is 0-indexed
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    };

    let reportData = [];
    let templateData = { 
        user: req.session.user, 
        startDate: startDate, 
        endDate: endDate 
    };
    let filename;

    // 1. DATA AGGREGATION & REPORT TYPE VALIDATION
    if (report_type === 'usage') {
        // --- USAGE HISTORY DATA LOGIC ---
        filename = `Usage_Report_${startDate}_to_${endDate}.${format}`;
        
        let selectedMeters = meterId !== 'all' ? masterMeterData.filter(m => m.id === meterId) : masterMeterData;
        let totalConsumption = 0;
        
        // CRITICAL FIX: Initialize dates using YYYY, M, D to guarantee local time (no T00:00:00 issues)
        const partsStart = startDate.split('-');
        let start = new Date(partsStart[0], partsStart[1] - 1, partsStart[2]); 
        
        const partsEnd = endDate.split('-');
        let end = new Date(partsEnd[0], partsEnd[1] - 1, partsEnd[2]);
        
        // Loop robustly from start date up to and including the end date
        while (start <= end) {
            
            const formattedDate = formatDate(start); 
            
            selectedMeters.forEach(meter => {
                const dailyUsage = Math.floor(Math.random() * (400 - 200 + 1)) + 200;
                
                reportData.push({
                    date: formattedDate, 
                    meterId: meter.id,
                    location: meter.location,
                    dailyUsage: dailyUsage.toFixed(0),
                });
                totalConsumption += dailyUsage;
            });
            
            // Move to the next day
            start.setDate(start.getDate() + 1);
        }

        templateData.meterId = meterId;
        templateData.reportData = reportData;
        templateData.totalConsumption = totalConsumption.toFixed(0);

    } else if (report_type === 'statement') {
        // --- ACCOUNT STATEMENT DATA LOGIC ---
        filename = `Account_Statement_${startDate}_to_${endDate}.${format}`;
        
        // Mock transaction data
        reportData = [
            { date: '2025-10-01', description: 'Starting Balance', debit: '0.00', credit: '0.00', balance: '250.00' },
            { date: '2025-10-05', description: 'Invoice INV-00126', debit: '465.50', credit: '0.00', balance: '-215.50' },
            { date: '2025-10-15', description: 'Payment Received', debit: '0.00', credit: '465.50', balance: '250.00' }
        ].filter(row => {
            // Filter mock data using YYYY, M, D initialization for consistency
            const partsRow = row.date.split('-');
            const rowDate = new Date(partsRow[0], partsRow[1] - 1, partsRow[2]);

            const partsStart = startDate.split('-');
            const startLimit = new Date(partsStart[0], partsStart[1] - 1, partsStart[2]);

            const partsEnd = endDate.split('-');
            const endLimit = new Date(partsEnd[0], partsEnd[1] - 1, partsEnd[2]);

            return rowDate >= startLimit && rowDate <= endLimit;
        });

    } else {
        // Fallback for an invalid report type value
        return res.status(400).send('Invalid report type requested.');
    }

    // 2. FORMAT GENERATION
    if (format === 'csv') {
        // --- CSV GENERATION LOGIC ---
        
        let csvContent = '';
        let headers;

        if (report_type === 'usage') {
            headers = ['Date', 'Meter ID', 'Location', 'Daily Usage (gal)'];
            // Double-check the structure here to ensure date property is accessed
            csvContent = reportData.map(row => 
                `${row.date},${row.meterId},"${row.location}",${row.dailyUsage}`
            ).join('\n');
            
        } else if (report_type === 'statement') {
            headers = ['Date', 'Description', 'Debit (SAR)', 'Credit (SAR)', 'Running Balance (SAR)'];
            csvContent = reportData.map(row => 
                `${row.date},"${row.description}",${row.debit},${row.credit},${row.balance}`
            ).join('\n');
        }
        
        // Prepend headers and send the file
        const finalCsv = headers.join(',') + '\n' + csvContent;

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        return res.send(finalCsv);

    } else if (format === 'pdf') {
        // --- PDF GENERATION LOGIC (Puppeteer/EJS) ---
        
        let templatePath;
        if (report_type === 'usage') {
            templatePath = path.join(__dirname, 'views', 'Customer', 'partials', 'usage-report.ejs');
        } else { // statement
            templatePath = path.join(__dirname, 'views', 'Customer', 'partials', 'account-statement.ejs');
        }
        
        try {
            const htmlContent = await ejs.renderFile(templatePath, templateData);

            const browser = await puppeteer.launch({ headless: true });
            const page = await browser.newPage();
            
            await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
            
            const pdfBuffer = await page.pdf({ 
                format: 'A4', 
                printBackground: true, 
                margin: {
                    top: '0.2in', right: '0.2in', bottom: '0.2in', left: '0.2in'
                }
            });

            await browser.close();

            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(pdfBuffer);
            
        } catch (error) {
            console.error(`${report_type} Report PDF Generation Failed:`, error.message);
            return res.status(500).send(`Error generating ${report_type === 'usage' ? 'Usage Report' : 'Account Statement'} PDF.`);
        }

    } else {
        // Fallback for an invalid format value
        return res.status(400).send('Invalid file format requested.');
    }
});