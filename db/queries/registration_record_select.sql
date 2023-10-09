select id, registration_record
from users
where username = $1;