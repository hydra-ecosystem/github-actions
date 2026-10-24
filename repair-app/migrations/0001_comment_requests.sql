-- Apply once to an existing slice-3 database before deploying comment support.
-- New databases use schema.sql, which already includes these columns/index.
ALTER TABLE requests ADD COLUMN comment_id INTEGER CHECK (comment_id > 0);
ALTER TABLE requests ADD COLUMN status_comment_id INTEGER CHECK (status_comment_id > 0);
ALTER TABLE requests ADD COLUMN selections_json TEXT;
CREATE UNIQUE INDEX one_comment_request
  ON requests (installation_id, repository_id, comment_id)
  WHERE comment_id IS NOT NULL;
