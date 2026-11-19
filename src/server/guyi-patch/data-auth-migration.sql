-- Privileged, additive migration. Never expose MySQL publicly.
-- Apply once, before installing the patched Database.php; do not run from the
-- CRUD-only web or broker account. No existing card or secret is rewritten.
ALTER TABLE cards ADD COLUMN IF NOT EXISTS data_epoch BIGINT NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS data_device_keys (
 card_id INT PRIMARY KEY,
 device_hash CHAR(64) NOT NULL,
 public_key CHAR(43) NOT NULL,
 data_epoch BIGINT NOT NULL,
 binding_id CHAR(64) NOT NULL,
 updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
