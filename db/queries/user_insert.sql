insert into users(username, registration_record)
values (
    $1,
    $2
)
returning id;