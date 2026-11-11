ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS source_ip Nullable(String) AFTER entity,
    ADD COLUMN IF NOT EXISTS user_name Nullable(String) AFTER source_ip;
