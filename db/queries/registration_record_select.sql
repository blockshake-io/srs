select id, client_public_key, masking_key, envelope, payload
from users
where username = $1;