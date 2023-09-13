create table users (
  id bigserial primary key,
  username text unique,
  masking_key text,
  client_public_key text,
  envelope text,
  payload text,
  created_at timestamp with time zone
);