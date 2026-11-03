CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  installation_id INTEGER NOT NULL CHECK (installation_id > 0),
  repository_id INTEGER NOT NULL CHECK (repository_id > 0),
  repository TEXT NOT NULL,
  pr INTEGER NOT NULL CHECK (pr > 0),
  head TEXT NOT NULL,
  base TEXT NOT NULL,
  dispatched_ref TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  check_id INTEGER NOT NULL CHECK (check_id > 0),
  actor_login TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  state TEXT NOT NULL CHECK (state IN ('reserved', 'dispatched', 'unknown', 'success', 'failure', 'cancelled')),
  run_id INTEGER CHECK (run_id > 0),
  run_url TEXT,
  html_url TEXT,
  conclusion TEXT,
  comment_id INTEGER CHECK (comment_id > 0),
  status_comment_id INTEGER CHECK (status_comment_id > 0),
  selections_json TEXT,
  trigger_key TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_request
  ON requests (installation_id, repository_id, pr)
  WHERE state IN ('reserved', 'dispatched', 'unknown');
CREATE UNIQUE INDEX IF NOT EXISTS one_comment_request
  ON requests (installation_id, repository_id, comment_id)
  WHERE comment_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS one_description_request
  ON requests (installation_id, repository_id, trigger_key)
  WHERE trigger_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS request_run
  ON requests (installation_id, repository_id, run_id);
CREATE INDEX IF NOT EXISTS request_check
  ON requests (installation_id, repository_id, check_id, created_at DESC);
CREATE INDEX IF NOT EXISTS terminal_completion
  ON requests (completed_at) WHERE state IN ('success', 'failure', 'cancelled');
CREATE TABLE IF NOT EXISTS selection_controls (
  installation_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  pr INTEGER NOT NULL,
  head TEXT NOT NULL,
  external_id TEXT NOT NULL,
  check_id INTEGER NOT NULL CHECK (check_id > 0),
  PRIMARY KEY (installation_id, repository_id)
);
