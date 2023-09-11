create table pending_registrations (
  session_id text primary key,
  username text,
  created_at timestamp with time zone,
  expires_at timestamp with time zone
);


create table pending_logins (
  session_id text primary key,
  username text,
  session_key text,
  expected_client_mac text,
  created_at timestamp with time zone,
  expires_at timestamp with time zone
);


create table users (
  id serial primary key,
  username text unique,
  masking_key text,
  client_public_key text,
  envelope text,
  payload text,
  created_at timestamp with time zone
)