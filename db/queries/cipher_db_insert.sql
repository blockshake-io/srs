insert into cipher_dbs(user_id, application_id, format, ciphertext)
values (
    $1,
    $2,
    $3,
    $4
)
returning id;