insert into cipher_data(user_id, key_version, application_id, format, ciphertext)
values (
    $1,
    $2,
    $3,
    $4,
    $5
)
returning id, created_at;