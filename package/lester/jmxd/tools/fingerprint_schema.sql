PRAGMA application_id = 1146570320;
PRAGMA user_version = 1;
PRAGMA foreign_keys = ON;

CREATE TABLE fingerprint_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE fingerprint_device (
  engine INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  vendor_id INTEGER NOT NULL DEFAULT 0,
  device_name TEXT NOT NULL,
  vendor_name TEXT NOT NULL DEFAULT '',
  device_type TEXT NOT NULL DEFAULT '',
  device_type_raw TEXT NOT NULL DEFAULT '',
  family TEXT NOT NULL DEFAULT '',
  os_class TEXT NOT NULL DEFAULT '',
  os_name TEXT NOT NULL DEFAULT '',
  best_image TEXT NOT NULL DEFAULT '',
  web_image TEXT NOT NULL DEFAULT '',
  sizes TEXT NOT NULL DEFAULT '',
  allow_oui_vendor INTEGER NOT NULL DEFAULT 0 CHECK (allow_oui_vendor IN (0, 1)),
  source_fb_id TEXT NOT NULL DEFAULT '',
  source_tm_id TEXT NOT NULL DEFAULT '',
  source_family_id TEXT NOT NULL DEFAULT '',
  source_os_class_id TEXT NOT NULL DEFAULT '',
  source_os_name_id TEXT NOT NULL DEFAULT '',
  source_vendor_id TEXT NOT NULL DEFAULT '',
  source_dev_type_id TEXT NOT NULL DEFAULT '',
  source_object_id TEXT NOT NULL DEFAULT '',
  source_name TEXT NOT NULL DEFAULT '',
  source_class_id TEXT NOT NULL DEFAULT '',
  source_ctag_id TEXT NOT NULL DEFAULT '',
  source_raw_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (engine, device_id)
) WITHOUT ROWID;

CREATE INDEX fingerprint_device_name
  ON fingerprint_device(device_name COLLATE NOCASE);
CREATE INDEX fingerprint_device_vendor
  ON fingerprint_device(vendor_name COLLATE NOCASE, vendor_id);
CREATE INDEX fingerprint_device_type
  ON fingerprint_device(device_type, family);

CREATE TABLE fingerprint_match_signal (
  engine INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  signal_type TEXT NOT NULL,
  ordinal INTEGER NOT NULL DEFAULT 0,
  value TEXT NOT NULL,
  PRIMARY KEY (engine, device_id, signal_type, ordinal),
  FOREIGN KEY (engine, device_id)
    REFERENCES fingerprint_device(engine, device_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX fingerprint_match_signal_lookup
  ON fingerprint_match_signal(signal_type, value COLLATE NOCASE);

CREATE TABLE fingerprint_score_weight (
  signal_type TEXT PRIMARY KEY,
  weight INTEGER NOT NULL CHECK (weight >= 0)
) WITHOUT ROWID;
