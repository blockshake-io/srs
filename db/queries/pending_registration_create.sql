insert into pending_registrations(session_id, username, created_at, expires_at)
values (
    $1,
    $2,
    current_timestamp,
    current_timestamp + ($3 || ' minutes')::interval
);