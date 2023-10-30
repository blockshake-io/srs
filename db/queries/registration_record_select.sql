select id, key_version, registration_record
from users
where username = $1;