create table users (
  id bigserial primary key,
  username text unique not null,
  registration_record json not null,
  created_at timestamptz not null,
  updated_at timestamptz,
  deleted_at timestamptz
);

create table cipher_dbs (
  id bigserial primary key,
  user_id bigint not null references users(id),
  application_id bigint not null,
  format text not null,
  ciphertext bytea not null,
  created_at timestamptz not null,
  updated_at timestamptz,
  deleted_at timestamptz
);