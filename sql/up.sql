CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  user_id SERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  registration_date TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS capabilities (
  label TEXT NOT NULL,
  user_id SERIAL,
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(user_id),
  UNIQUE (label, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id UUID PRIMARY KEY,
  user_id SERIAL,
  expiration_date TIMESTAMPTZ NOT NULL,
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(user_id)
);
