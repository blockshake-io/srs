delete from pending_logins
where
    session_id = $1 and
    current_timestamp < expires_at
returning *;