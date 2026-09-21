const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

function ensureDirectories(rootDir) {
  const dataDir = path.join(rootDir, 'data');
  const uploadsDir = path.join(dataDir, 'uploads');

  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });

  return { dataDir, uploadsDir };
}

function createDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is required. Configure a PostgreSQL database before starting the server.');
  }

  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false } });
  const query = (sql, params, callback) => {
    const values = Array.isArray(params) ? params : [];
    const resultCallback = typeof params === 'function' ? params : callback;
    let parameterIndex = 0;
    const postgresSql = sql.replace(/\?/g, () => `$${++parameterIndex}`);
    pool.query(postgresSql, values, (err, result) => resultCallback?.(err, result));
  };

  return {
    query,
    run(sql, params, callback) {
      query(sql, params, (err, result) => callback?.(err, result));
    },
    get(sql, params, callback) {
      query(sql, params, (err, result) => (typeof params === 'function' ? params : callback)?.(err, result?.rows[0]));
    },
    all(sql, params, callback) {
      query(sql, params, (err, result) => (typeof params === 'function' ? params : callback)?.(err, result?.rows || []));
    },
    end() {
      return pool.end();
    }
  };
}

function initDatabase(db) {
  const statements = [
    `
        CREATE TABLE IF NOT EXISTS visitors (
          id SERIAL PRIMARY KEY,
          visitor_id TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL,
          user_info TEXT
        )
      `,
    `
        CREATE TABLE IF NOT EXISTS logs (
          id SERIAL PRIMARY KEY,
          visitor_id TEXT,
          event_name TEXT NOT NULL,
          details TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY(visitor_id) REFERENCES visitors(visitor_id)
        )
      `,
    `
        CREATE TABLE IF NOT EXISTS files (
          id TEXT PRIMARY KEY,
          file_name TEXT NOT NULL,
          stored_name TEXT NOT NULL,
          storage_key TEXT,
          download_slug TEXT,
          content_type TEXT,
          file_size INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT,
          uploader_ip TEXT,
          uploader_session TEXT,
          password_hash TEXT,
          auto_delete INTEGER NOT NULL DEFAULT 1,
          download_count INTEGER NOT NULL DEFAULT 0,
          opened_count INTEGER NOT NULL DEFAULT 0,
          is_bundle INTEGER NOT NULL DEFAULT 0
        )
      `,
    ...['storage_key TEXT', 'download_slug TEXT', 'expires_at TEXT', 'uploader_ip TEXT', 'uploader_session TEXT', 'password_hash TEXT', 'auto_delete INTEGER NOT NULL DEFAULT 1',
      'download_count INTEGER NOT NULL DEFAULT 0', 'opened_count INTEGER NOT NULL DEFAULT 0',
      'is_bundle INTEGER NOT NULL DEFAULT 0'].map((column) => `ALTER TABLE files ADD COLUMN IF NOT EXISTS ${column}`),
    `
        CREATE TABLE IF NOT EXISTS abuse_reports (
          id SERIAL PRIMARY KEY,
          file_id TEXT NOT NULL,
          reason TEXT NOT NULL,
          details TEXT,
          reporter_ip TEXT,
          created_at TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open'
        )
      `
  ];

  return statements.reduce((promise, statement) => promise.then(() => new Promise((resolve, reject) => {
    db.query(statement, [], (err) => err ? reject(err) : resolve());
  })), Promise.resolve());
}

module.exports = { ensureDirectories, createDatabase, initDatabase };
