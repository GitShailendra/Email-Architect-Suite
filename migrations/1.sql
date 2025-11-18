
CREATE TABLE sequences (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  user_id TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE email_blocks (
  id TEXT PRIMARY KEY,
  sequence_id TEXT NOT NULL,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  subject_line TEXT,
  preview_text TEXT,
  body_copy TEXT,
  cta_text TEXT,
  cta_url TEXT,
  send_delay_hours INTEGER DEFAULT 0,
  position_x INTEGER DEFAULT 0,
  position_y INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sequence_connections (
  id TEXT PRIMARY KEY,
  sequence_id TEXT NOT NULL,
  source_block_id TEXT NOT NULL,
  target_block_id TEXT NOT NULL,
  condition_type TEXT DEFAULT 'default',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sequences_user_id ON sequences(user_id);
CREATE INDEX idx_email_blocks_sequence_id ON email_blocks(sequence_id);
CREATE INDEX idx_connections_sequence_id ON sequence_connections(sequence_id);
