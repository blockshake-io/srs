select id, user_id, format, application_id, ciphertext, created_at
from cipher_dbs
where id = $1;