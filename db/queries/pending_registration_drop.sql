delete from pending_registrations
where
    session_id = $1 and
    current_timestamp < expires_at
returning *;