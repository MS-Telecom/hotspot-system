-- Legacy cleanup: radreply is no longer used by the backend.
-- After validating in production, you can safely drop the table.

DROP TABLE IF EXISTS radreply;
