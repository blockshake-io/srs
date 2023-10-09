insert into users(username, registration_record, created_at)
values (
    $1,
    $2,
    current_timestamp
)
returning id;