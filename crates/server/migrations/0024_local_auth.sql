-- Local-first auth. Replaces WorkOS; billing/Pro entitlement is dropped so any
-- authenticated user can sync. Old WorkOS account_ids (user_*) are orphaned;
-- clients re-register and re-sync from their local-first copy.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    email_verified_at TIMESTAMPTZ,
    display_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_email_len CHECK (char_length(email) BETWEEN 3 AND 320)
);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider TEXT NOT NULL,
    provider_sub TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, provider_sub),
    UNIQUE (provider, user_id),
    CONSTRAINT oauth_provider_len CHECK (char_length(provider) BETWEEN 1 AND 64),
    CONSTRAINT oauth_sub_len CHECK (char_length(provider_sub) BETWEEN 1 AND 512)
);
CREATE INDEX IF NOT EXISTS oauth_accounts_user_idx ON oauth_accounts (user_id);

-- Opaque sessions: only SHA-256(token) is stored, never the raw token.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip INET,
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_user_expires_idx ON sessions (user_id, expires_at);

CREATE TABLE IF NOT EXISTS email_verification_codes (
    user_id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS password_reset_user_idx ON password_reset_tokens (user_id);

CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    code_verifier TEXT,
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_state_len CHECK (char_length(state) BETWEEN 16 AND 512)
);
