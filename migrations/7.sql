
CREATE TABLE user_credits (
  user_id TEXT PRIMARY KEY,
  credits_balance INTEGER DEFAULT 10000,
  total_credits_used INTEGER DEFAULT 0,
  last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);
