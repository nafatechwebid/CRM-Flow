-- Jalankan sekali di Cloudflare D1 (tab Console)
CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  salt  TEXT NOT NULL,
  hash  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS docs (
  collection TEXT NOT NULL,
  id         TEXT NOT NULL,
  data       TEXT NOT NULL,
  updated    INTEGER NOT NULL,
  PRIMARY KEY (collection, id)
);
CREATE INDEX IF NOT EXISTS idx_docs_collection ON docs(collection);
