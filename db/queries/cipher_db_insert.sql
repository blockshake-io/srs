insert into cipher_dbs(user_id, application_id, format, ciphertext, created_at)
values (
    $1,
    $2,
    $3,
    $4,
    current_timestamp
)
returning id;