const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { ensureDirectories, createDatabase, initDatabase } = require('./db');
const { purgeExpiredFiles, escapeHtml, isExpired, hashPassword, expiryFromHours, sanitizeFileName, MAX_FILE_SIZE } = require('./utils');
const createApiRoutes = require('../api/routes');

function createApp(rootDir = path.resolve(__dirname, '..')) {
  const projectRoot = rootDir;
  const publicDir = path.join(projectRoot, 'public');
  const app = express();
  const { dataDir, uploadsDir } = ensureDirectories(projectRoot);

  const db = createDatabase();
  initDatabase(db).then(() => {
    console.log('PostgreSQL database ready.');
  }).catch((err) => {
    console.error('Database initialization failed:', err.message);
    process.exit(1);
  });

  const smtpPort = Number(process.env.SMTP_PORT || 587);
  const smtpSecure = smtpPort === 465 || (smtpPort !== 587 && process.env.SMTP_SECURE === 'true');

  let mailTransporter = null;
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: smtpPort,
      secure: smtpSecure,
      requireTLS: smtpPort === 587,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });

    mailTransporter.verify()
      .then(() => console.log('SMTP connection verified.'))
      .catch((error) => console.error('SMTP verification failed:', error.message));
  } else {
    console.warn('SMTP is not configured. Direct email sending is disabled.');
  }

  app.use(express.json({ limit: '2mb' }));
  app.use(express.raw({ type: 'application/octet-stream', limit: `${MAX_FILE_SIZE}b` }));
  app.use(express.static(publicDir));

  app.use('/api', createApiRoutes({
    db,
    uploadsDir,
    mailTransporter,
    expiryFromHours,
    hashPassword,
    isExpired,
    removeFile: require('./utils').removeFile,
    escapeHtml
  }));

  app.use((error, req, res, next) => {
    if (error.type === 'entity.too.large') {
      return res.status(413).json({ ok: false, error: 'Files must be 1 GB or smaller.' });
    }
    return next(error);
  });

  app.get('/share/:id', (req, res) => {
    db.get('SELECT id, file_name, password_hash, expires_at FROM files WHERE id = ?', [req.params.id], (err, row) => {
      if (err || !row) return res.status(404).send('File not found.');
      if (isExpired(row)) return res.status(410).send('This link has expired.');

      const title = escapeHtml(row.file_name);
      const passwordForm = row.password_hash ? `
        <form method="get" action="/api/files/${encodeURIComponent(row.id)}/download">
          <label>Password required</label>
          <input name="password" type="password" required autofocus placeholder="Enter password">
          <input type="hidden" name="inline" value="1">
          <button type="submit">Download file</button>
        </form>` : `<a href="/api/files/${encodeURIComponent(row.id)}/download?inline=1">Open or download file</a>`;

      res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share ${title}</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07111f;color:#e5eefb;font:16px Segoe UI,Arial,sans-serif}main{width:min(90%,420px);padding:28px;border:1px solid #334155;border-radius:18px;background:#111827}h1{font-size:1.4rem;word-break:break-word}form{display:grid;gap:12px}input,button,a{padding:12px;border-radius:9px;font:inherit}input{border:1px solid #475569;background:#0f172a;color:#fff}button,a{border:0;background:#7c3aed;color:#fff;text-align:center;text-decoration:none;cursor:pointer}</style></head><body><main><h1>${title}</h1>${passwordForm}</main></body></html>`);
    });
  });

  app.get('*', (req, res) => {
    const indexPath = path.join(publicDir, 'index.html');
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }
    res.sendFile(path.join(projectRoot, 'index.html'));
  });

  setInterval(() => purgeExpiredFiles(db, uploadsDir), 15 * 60 * 1000).unref();

  return { app, db, uploadsDir, dataDir };
}

module.exports = { createApp };
