
-- Add user_id column to sequences table if not already present
-- Update sequences to use proper user authentication
CREATE TABLE IF NOT EXISTS user_sequences (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  user_id TEXT NOT NULL,
  is_template BOOLEAN DEFAULT FALSE,
  template_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add template and sharing features
CREATE TABLE IF NOT EXISTS sequence_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  created_by_user_id TEXT NOT NULL,
  is_public BOOLEAN DEFAULT FALSE,
  sequence_data TEXT NOT NULL, -- JSON data for the sequence
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add export tracking
CREATE TABLE IF NOT EXISTS sequence_exports (
  id TEXT PRIMARY KEY,
  sequence_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  export_type TEXT NOT NULL, -- 'csv', 'html', 'txt', 'json'
  export_format TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
