CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT 'ADAMOVIES User',
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin','super_admin')),
  download_credits INTEGER NOT NULL DEFAULT 0 CHECK (download_credits >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS movies (
  id BIGSERIAL PRIMARY KEY,
  tmdb_id INTEGER UNIQUE NOT NULL,
  title TEXT NOT NULL,
  overview TEXT,
  release_date DATE,
  poster_path TEXT,
  backdrop_path TEXT,
  runtime_minutes INTEGER NOT NULL CHECK (runtime_minutes >= 90),
  tmdb_rating NUMERIC(3,1),
  genres TEXT[] NOT NULL DEFAULT '{}',
  cast_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  mux_playback_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft','published','unpublished','deleted')),
  uploaded_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trending_movies (
  movie_id BIGINT PRIMARY KEY REFERENCES movies(id) ON DELETE CASCADE,
  position INTEGER NOT NULL DEFAULT 0,
  added_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credit_ledger (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('credit','debit')),
  amount INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS downloads (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  movie_id BIGINT NOT NULL REFERENCES movies(id),
  used_free_period BOOLEAN NOT NULL DEFAULT FALSE,
  credits_spent INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ad_rewards (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reward_id TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS movies_status_idx ON movies(status);
CREATE INDEX IF NOT EXISTS movies_created_idx ON movies(created_at DESC);
CREATE INDEX IF NOT EXISTS trending_position_idx ON trending_movies(position);
CREATE INDEX IF NOT EXISTS downloads_user_idx ON downloads(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ledger_user_idx ON credit_ledger(user_id, created_at DESC);

-- After registering your first account:
-- UPDATE users SET role='super_admin' WHERE email='YOUR_EMAIL';
