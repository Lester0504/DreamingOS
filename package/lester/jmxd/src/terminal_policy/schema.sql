-- Terminal Policy Schema v1
-- Separate database: /etc/dreamingwrt/terminal_policy.db

CREATE TABLE IF NOT EXISTS policies (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL DEFAULT "",
    remark              TEXT NOT NULL DEFAULT "",
    enabled             INTEGER NOT NULL DEFAULT 1,

    rate_upload_kbps    INTEGER NOT NULL DEFAULT 0,
    rate_download_kbps  INTEGER NOT NULL DEFAULT 0,
    rate_mode           TEXT NOT NULL DEFAULT "per_ip",

    started_at          INTEGER NOT NULL DEFAULT 0,
    duration_count      INTEGER NOT NULL DEFAULT 0,
    duration_unit       TEXT NOT NULL DEFAULT "days",
    deadline_at         INTEGER NOT NULL DEFAULT 0,

    quota_bytes         INTEGER NOT NULL DEFAULT 0,
    quota_accounting    TEXT NOT NULL DEFAULT "upload_plus_download",
    quota_mode          TEXT NOT NULL DEFAULT "per_ip",

    deny_protocols      TEXT NOT NULL DEFAULT "",

    status              TEXT NOT NULL DEFAULT "active",
    last_transition_at  INTEGER NOT NULL DEFAULT 0,
    generation          INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,

    CHECK (rate_upload_kbps >= 0),
    CHECK (rate_download_kbps >= 0),
    CHECK (duration_count >= 0),
    CHECK (quota_bytes >= 0)
);

CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_policies_deadline ON policies(deadline_at);

CREATE TABLE IF NOT EXISTS targets (
    policy_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    family      INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    prefix_len  INTEGER NOT NULL,
    PRIMARY KEY (policy_id, family, prefix)
);

CREATE TABLE IF NOT EXISTS quota_usage (
    policy_id       TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,
    used_upload_bytes   INTEGER NOT NULL DEFAULT 0,
    used_download_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes      INTEGER NOT NULL DEFAULT 0,
    checkpoint_at   INTEGER NOT NULL DEFAULT 0
);
