CREATE TABLE login_attempts (
  email TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL,
  window_started_at INTEGER NOT NULL,
  locked_until INTEGER
);
