CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  pr INTEGER NOT NULL,
  head TEXT NOT NULL,
  check_id INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  installation INTEGER NOT NULL,
  status TEXT NOT NULL,
  run_id INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS requests_created_at ON requests (created_at);
