insert into users(username, key_version, registration_record)
values (
    $1,
    $2,
    $3
)
returning id;