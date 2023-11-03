create table users (
  id bigserial primary key,
  username text unique not null,
  key_version bigint not null,
  registration_record json not null,
  created_at timestamp not null default (now() at time zone 'utc'),
  updated_at timestamp,
  deleted_at timestamp
);

create table cipher_data (
  id bigserial primary key,
  user_id bigint not null references users(id),
  key_version bigint not null,
  application_id bigint not null,
  format text not null,
  ciphertext bytea not null,
  created_at timestamp not null default (now() at time zone 'utc'),
  updated_at timestamp,
  deleted_at timestamp
);