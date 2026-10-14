CREATE TABLE IF NOT EXISTS users (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email      text UNIQUE NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  id            text PRIMARY KEY,
  name          text NOT NULL DEFAULT '',
  redirect_uris text[] NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash      bytea PRIMARY KEY,
  client_id      text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri   text NOT NULL,
  code_challenge text NOT NULL,
  expires_at     timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash bytea PRIMARY KEY,
  kind       text NOT NULL CHECK (kind IN ('access', 'refresh')),
  client_id  text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credentials (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  system     text NOT NULL,
  sealed     bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, system)
);

CREATE TABLE IF NOT EXISTS personal_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         text NOT NULL,
  token_hash   bytea UNIQUE NOT NULL,
  tools        text[] NOT NULL,
  scope        jsonb NOT NULL DEFAULT '{}',
  expires_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
