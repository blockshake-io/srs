insert into users(username, masking_key, client_public_key, envelope, payload, created_at)
values (
    $1,
    $2,
    $3,
    $4,
    $5,
    current_timestamp
)
returning id;