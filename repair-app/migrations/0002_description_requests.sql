-- Apply once after 0001, before deploying description-trigger support.
-- New databases use schema.sql instead. Existing rows and locks are retained.
ALTER TABLE requests ADD COLUMN trigger_key TEXT;
CREATE UNIQUE INDEX one_description_request
  ON requests (installation_id, repository_id, trigger_key)
  WHERE trigger_key IS NOT NULL;
