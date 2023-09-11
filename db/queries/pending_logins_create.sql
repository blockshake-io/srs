insert into pending_logins(session_id, username, session_key, expected_client_mac, created_at, expires_at)
values (
    $1,
    $2,
    $3,
    $4,
    current_timestamp,
    current_timestamp + ($5 || ' minutes')::interval
);