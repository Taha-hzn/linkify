const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MAX_FILE_SIZE = 1024 * 1024 * 1024;

function sanitizeFileName(fileName) {
  const clean = (fileName || 'download.bin')
    .replace(/[\\/]+/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  return clean || 'download.bin';
}

function expiryFromHours(value) {
  const hours = Number(value);
  if (![1, 24, 168].includes(hours)) return null;
  return new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
}

function hashPassword(password) {
  return password ? crypto.createHash('sha256').update(String(password)).digest('hex') : null;
}

function isExpired(row) {
  return row.expires_at && Date.parse(row.expires_at) <= Date.now();
}

function removeFile({ db, uploadsDir }, row, callback) {
  fs.rm(path.join(uploadsDir, row.stored_name), { force: true }, () => {
    db.run('DELETE FROM files WHERE id = ?', [row.id], callback);
  });
}

function purgeExpiredFiles(db, uploadsDir) {
  db.all('SELECT * FROM files WHERE auto_delete = 1 AND expires_at IS NOT NULL AND expires_at <= ?', [new Date().toISOString()], (err, rows) => {
    if (!err) {
      rows.forEach((row) => removeFile({ db, uploadsDir }, row, () => {}));
    }
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

module.exports = {
  MAX_FILE_SIZE,
  sanitizeFileName,
  expiryFromHours,
  hashPassword,
  isExpired,
  removeFile,
  purgeExpiredFiles,
  escapeHtml
};
