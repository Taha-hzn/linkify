# Operations checklist

# Database

The application uses an external PostgreSQL database. Set `DATABASE_URL` in the deployment environment before starting the server. Set `DATABASE_SSL=false` only when the PostgreSQL server does not support TLS. The `data` directory is used for uploaded files only; no local database is created.

## Billing alerts

Configure storage and request/operation budget alerts in the storage provider and hosting provider before production. Recommended thresholds are 50%, 80%, and 100% of the monthly budget, with a separate alert for unusual upload and download request volume. The application rate-limits uploads, but provider-level alerts are still required because billing settings are account-specific.

## Malware scanning

The current service accepts uploads and exposes them after the upload completes. For production, place a quarantine state in the `files` table, scan each stored object with ClamAV or a scanning API, and only allow downloads when the scan status is clean. Failed or timed-out scans should remain unavailable until reviewed.

## Monitoring

Poll `GET /api/health` from an uptime monitor and alert on non-2xx responses, latency, and database failures. Collect server logs and alert on repeated 429 responses, upload errors, and report submissions. Do not expose `/api/logs` publicly without authentication before production.
