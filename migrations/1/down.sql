npx wrangler d1 execute 019a4aae-fab8-7958-8a4d-c57847a48b37 --local --command "CREATE TABLE IF NOT EXISTS user_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL, token TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL); CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token); CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);"

DROP INDEX idx_connections_sequence_id;
DROP INDEX idx_email_blocks_sequence_id;
DROP INDEX idx_sequences_user_id;
DROP TABLE sequence_connections;
DROP TABLE email_blocks;
DROP TABLE sequences;
