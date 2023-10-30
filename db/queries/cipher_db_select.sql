select id, user_id, key_version, format, application_id, ciphertext, created_at
from cipher_dbs
where id = $1;