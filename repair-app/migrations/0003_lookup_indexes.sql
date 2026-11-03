-- Apply after 0002 before deploying direct selection-control lookups.
-- Existing requests, replay identities and active locks are unchanged.
CREATE INDEX IF NOT EXISTS request_run
  ON requests (installation_id, repository_id, run_id);
CREATE INDEX IF NOT EXISTS request_check
  ON requests (installation_id, repository_id, check_id, created_at DESC);
CREATE INDEX IF NOT EXISTS terminal_completion
  ON requests (completed_at) WHERE state IN ('success', 'failure', 'cancelled');
-- One replaceable locator per installed repository, not one row per edit or PR.
CREATE TABLE IF NOT EXISTS selection_controls (
  installation_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  pr INTEGER NOT NULL,
  head TEXT NOT NULL,
  external_id TEXT NOT NULL,
  check_id INTEGER NOT NULL CHECK (check_id > 0),
  PRIMARY KEY (installation_id, repository_id)
);
