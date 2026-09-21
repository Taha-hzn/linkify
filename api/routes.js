const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const archiver = require('archiver');
const { MAX_FILE_SIZE } = require('../app/utils');

module.exports = function createApiRoutes({
  db,
  uploadsDir,
  mailTransporter,
  expiryFromHours,
  hashPassword,
  isExpired,
  removeFile,
  escapeHtml
}) {
  const router = require('express').Router();
  const uploadAttempts = new Map();
  const uploadWindowMs = 60 * 60 * 1000;
  const maxUploadsPerWindow = 20;

  function clientAddress(req) {
    return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  }

  function isUploadRateLimited(req) {
    const now = Date.now();
    const address = clientAddress(req);
    const recent = (uploadAttempts.get(address) || []).filter((timestamp) => now - timestamp < uploadWindowMs);
    recent.push(now);
    uploadAttempts.set(address, recent);
    return recent.length > maxUploadsPerWindow;
  }

  function ensureUploadStorage() {
    try {
      fs.mkdirSync(uploadsDir, { recursive: true });
      return true;
    } catch (error) {
      console.error('Failed to prepare file storage:', error.message);
      return false;
    }
  }

  router.get('/health', (req, res) => {
    res.json({ ok: true, message: 'Server is running', database: 'PostgreSQL' });
  });

  router.post('/files', require('express').raw({ type: '*/*', limit: `${MAX_FILE_SIZE}b` }), (req, res) => {
    if (!ensureUploadStorage()) {
      return res.status(503).json({ ok: false, error: 'File storage is not configured.' });
    }

    if (isUploadRateLimited(req)) {
      return res.status(429).json({ ok: false, error: 'Upload limit reached. Please try again later.' });
    }

    const fileBuffer = req.body;
    const fileName = require('./../app/utils').sanitizeFileName(req.headers['x-file-name'] || 'download.bin');
    const contentType = req.headers['content-type'] || 'application/octet-stream';
    const expiresAt = expiryFromHours(req.headers['x-expires-hours']);
    const passwordHash = hashPassword(req.headers['x-file-password']);

    if (!fileBuffer || fileBuffer.length === 0) {
      return res.status(400).json({ ok: false, error: 'No file content was provided.' });
    }

    if (fileBuffer.length > MAX_FILE_SIZE) {
      return res.status(413).json({ ok: false, error: 'Files must be 1 GB or smaller.' });
    }

    const fileId = crypto.randomUUID();
    const storedName = `${fileId}.bin`;
    const filePath = path.join(uploadsDir, storedName);

    fs.writeFile(filePath, fileBuffer, (err) => {
      if (err) {
        console.error('Failed to save uploaded file:', err.message);
        return res.status(500).json({ ok: false, error: 'Failed to save uploaded file.' });
      }

      db.run(
        `INSERT INTO files (id, file_name, stored_name, storage_key, download_slug, content_type, file_size, created_at, expires_at, uploader_ip, uploader_session, password_hash, auto_delete)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [fileId, fileName, storedName, storedName, fileId, contentType, fileBuffer.length, new Date().toISOString(), expiresAt, clientAddress(req), req.headers['x-session-id'] || null, passwordHash, req.headers['x-auto-delete'] !== 'false' ? 1 : 0],
        (insertErr) => {
          if (insertErr) {
            console.error('Failed to save file metadata:', insertErr.message);
            return res.status(500).json({ ok: false, error: 'Failed to save file record.' });
          }

          res.json({
            ok: true,
            fileId,
            fileName,
            downloadUrl: `/api/files/${fileId}/download`,
            shareUrl: `/share/${fileId}`,
            expiresAt,
            protected: Boolean(passwordHash)
          });
        }
      );
    });
  });

  router.post('/reports', (req, res) => {
    const { fileId, reason, details } = req.body || {};
    const allowedReasons = ['malware', 'copyright', 'illegal', 'privacy', 'other'];
    if (!fileId || !allowedReasons.includes(reason)) {
      return res.status(400).json({ ok: false, error: 'A valid file ID and report reason are required.' });
    }

    db.get('SELECT id FROM files WHERE id = ?', [fileId], (lookupErr, row) => {
      if (lookupErr || !row) return res.status(404).json({ ok: false, error: 'File not found.' });
      db.run(
        'INSERT INTO abuse_reports (file_id, reason, details, reporter_ip, created_at) VALUES (?, ?, ?, ?, ?)',
        [fileId, reason, String(details || '').slice(0, 2000), clientAddress(req), new Date().toISOString()],
        (reportErr) => {
          if (reportErr) return res.status(500).json({ ok: false, error: 'Could not submit the report.' });
          res.status(201).json({ ok: true, message: 'Report received.' });
        }
      );
    });
  });

  router.post('/bundles', (req, res) => {
    if (!ensureUploadStorage()) {
      return res.status(503).json({ ok: false, error: 'File storage is not configured.' });
    }

    const { fileIds, fileName, expiresHours, password, autoDelete = true } = req.body || {};

    if (!Array.isArray(fileIds) || fileIds.length < 2) {
      return res.status(400).json({ ok: false, error: 'At least two files are required.' });
    }

    db.all(`SELECT * FROM files WHERE id IN (${fileIds.map(() => '?').join(',')})`, fileIds, async (err, rows) => {
      if (err || rows.length !== fileIds.length) {
        return res.status(400).json({ ok: false, error: 'One or more files could not be found.' });
      }

      const fileId = crypto.randomUUID();
      const storedName = `${fileId}.zip`;
      const output = fs.createWriteStream(path.join(uploadsDir, storedName));
      const archive = archiver('zip', { zlib: { level: 9 } });

      archive.on('error', () => res.status(500).json({ ok: false, error: 'Failed to create ZIP file.' }));
      output.on('close', () => {
        const expiresAt = expiryFromHours(expiresHours);
        db.run(
          `INSERT INTO files (id, file_name, stored_name, storage_key, download_slug, content_type, file_size, created_at, expires_at, uploader_ip, uploader_session, password_hash, auto_delete, is_bundle)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
          [fileId, require('./../app/utils').sanitizeFileName(fileName || 'linkify-files.zip'), storedName, storedName, fileId, 'application/zip', archive.pointer(), new Date().toISOString(), expiresAt, clientAddress(req), req.headers['x-session-id'] || null, hashPassword(password), autoDelete ? 1 : 0],
          (insertErr) => {
            if (insertErr) {
              return res.status(500).json({ ok: false, error: 'Failed to save ZIP metadata.' });
            }

            return res.json({
              ok: true,
              fileId,
              fileName: fileName || 'linkify-files.zip',
              downloadUrl: `/api/files/${fileId}/download`,
              shareUrl: `/share/${fileId}`,
              expiresAt,
              protected: Boolean(password)
            });
          }
        );
      });

      archive.pipe(output);
      rows.forEach((row) => archive.file(path.join(uploadsDir, row.stored_name), { name: row.file_name }));
      archive.finalize();
    });
  });

  router.get('/files/:id/analytics', (req, res) => {
    db.get('SELECT id, file_name, created_at, expires_at, download_count, opened_count FROM files WHERE id = ?', [req.params.id], (err, row) => {
      if (err || !row) {
        return res.status(404).json({ ok: false, error: 'File not found.' });
      }

      db.all("SELECT created_at, details FROM logs WHERE event_name IN ('file_opened', 'file_downloaded') AND details LIKE ? ORDER BY created_at DESC LIMIT 100", [`%${req.params.id}%`], (logErr, events) => {
        res.json({ ok: true, file: row, events: logErr ? [] : events });
      });
    });
  });

  router.post('/webhooks', async (req, res) => {
    const { url, link, services } = req.body || {};
    if (!url || !/^https?:\/\//i.test(url)) {
      return res.status(400).json({ ok: false, error: 'A valid webhook URL is required.' });
    }

    try {
      const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: `New Linkify file link: ${link}`, text: `New Linkify file link: ${link}`, services }) });
      if (!response.ok) throw new Error(`Webhook returned ${response.status}`);
      res.json({ ok: true });
    } catch (error) {
      res.status(502).json({ ok: false, error: error.message });
    }
  });

  router.post('/email', async (req, res) => {
    const { recipients, link, fileName } = req.body || {};
    const emailList = Array.isArray(recipients) ? recipients : String(recipients || '').split(',');
    const validRecipients = emailList.map((email) => email.trim()).filter((email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));

    if (!validRecipients.length || !link) {
      return res.status(400).json({ ok: false, error: 'Enter at least one valid recipient and generate a link first.' });
    }

    if (!mailTransporter) {
      return res.status(503).json({ ok: false, error: 'Direct email is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS on the server.' });
    }

    try {
      await mailTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: validRecipients,
        subject: `Shared file from Linkify${fileName ? `: ${fileName}` : ''}`,
        text: `A file was shared with you through Linkify.\n\nOpen the file: ${link}`
      });
      res.json({ ok: true, recipients: validRecipients });
    } catch (error) {
      console.error('Direct email failed:', error.message);
      res.status(502).json({ ok: false, error: `Email delivery failed: ${error.message}` });
    }
  });

  router.get('/files/:id/download', (req, res) => {
    const { id } = req.params;

    db.get('SELECT * FROM files WHERE id = ?', [id], (err, row) => {
      if (err) {
        console.error('Error reading file metadata:', err.message);
        return res.status(500).json({ ok: false, error: 'Failed to fetch file metadata.' });
      }

      if (!row) {
        return res.status(404).json({ ok: false, error: 'File not found.' });
      }

      if (isExpired(row)) {
        if (row.auto_delete) {
          removeFile({ db, uploadsDir }, row, () => {});
        }
        return res.status(410).json({ ok: false, error: 'This link has expired.' });
      }

      if (row.password_hash && hashPassword(req.query.password) !== row.password_hash) {
        return res.status(401).json({ ok: false, error: 'Password required.', protected: true });
      }

      const filePath = path.join(uploadsDir, row.stored_name);
      db.run('UPDATE files SET download_count = download_count + 1, opened_count = opened_count + 1 WHERE id = ?', [id]);
      db.run('INSERT INTO logs (event_name, details, created_at) VALUES (?, ?, ?)', ['file_downloaded', JSON.stringify({ fileId: id, fileName: row.file_name }), new Date().toISOString()]);
      const stream = fs.createReadStream(filePath);

      stream.on('error', (streamErr) => {
        console.error('Error streaming file:', streamErr.message);
        if (!res.headersSent) {
          res.status(404).json({ ok: false, error: 'File could not be streamed.' });
        }
      });

      res.setHeader('Content-Type', row.content_type || 'application/octet-stream');
      res.setHeader('Content-Length', row.file_size);
      const disposition = req.query.inline === '1' ? 'inline' : 'attachment';
      res.setHeader('Content-Disposition', `${disposition}; filename="${String(row.file_name).replace(/"/g, '\\"')}"`);
      stream.pipe(res);
    });
  });

  router.get('/logs', (req, res) => {
    db.all('SELECT * FROM logs ORDER BY id DESC LIMIT 100', (err, rows) => {
      if (err) {
        console.error('Error reading logs:', err.message);
        return res.status(500).json({ ok: false, error: 'Failed to fetch logs' });
      }
      res.json({ ok: true, logs: rows });
    });
  });

  router.post('/logs', (req, res) => {
    const { visitorId, userInfo, event, details } = req.body || {};
    if (!event) {
      return res.status(400).json({ ok: false, error: 'Event name is required' });
    }

    const createdAt = new Date().toISOString();
    const safeDetails = details && typeof details === 'object' ? JSON.stringify(details) : JSON.stringify({});
    const safeUserInfo = userInfo && typeof userInfo === 'object' ? JSON.stringify(userInfo) : null;

    if (visitorId) {
      db.run(
        `INSERT INTO visitors (visitor_id, created_at, user_info) VALUES (?, ?, ?)
         ON CONFLICT(visitor_id) DO UPDATE SET user_info = excluded.user_info`,
        [visitorId, createdAt, safeUserInfo],
        (insertErr) => {
          if (insertErr) {
            console.error('Visitor insert failed:', insertErr.message);
          }
        }
      );
    }

    db.run(
      `INSERT INTO logs (visitor_id, event_name, details, created_at) VALUES (?, ?, ?, ?)`,
      [visitorId || null, event, safeDetails, createdAt],
      (err) => {
        if (err) {
          console.error('Log insert failed:', err.message);
          return res.status(500).json({ ok: false, error: 'Failed to save log' });
        }
        res.json({ ok: true, message: 'Log saved successfully' });
      }
    );
  });

  return router;
};
