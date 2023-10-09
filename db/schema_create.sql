create table users (
  id bigserial primary key,
  username text unique not null,
  registration_record json not null,
  created_at timestamptz not null,
  updated_at timestamptz,
  deleted_at timestamptz
);