use aes_gcm::{aead::Aead, aes::Aes256, AeadCore, Aes256Gcm, AesGcm, KeyInit};
use generic_array::{typenum, GenericArray};
use rand::thread_rng;
use rand_core::OsRng;
use reqwest::{
    blocking::multipart,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use srs::{
    error::{ErrorCode, Source},
    http::indexer::{
        authenticate::{
            AuthenticateStep1Request, AuthenticateStep1Response, AuthenticateStep2Request,
            AuthenticateStep2Response,
        },
        cipher_data::GetChiperDbsResponse,
        registration::{RegisterStep1Request, RegisterStep1Response, RegisterStep2Request},
    },
    ksf::KsfParams,
    Error, Result,
};
use srs_opaque::{
    ciphersuite::{AuthCode, Digest},
    keypair::PublicKey,
    messages::RegistrationRecord,
    opaque::{ClientLoginFlow, ClientRegistrationFlow},
    primitives::{self, derive_keypair},
};
use std::{io::{stdin, stdout, Write}, time::Instant};
use tempfile::NamedTempFile;
use typenum::{Unsigned, U12, U32};

const SERVER_IDENTITY: &str = "srs.blockshake.io";
const ENCRYPTION_KEY: &[u8; 13] = b"EncryptionKey";
type NonceSize = U12;

fn argon2_stretch(input: &[u8], params: &KsfParams) -> srs_opaque::Result<Digest> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            params.output_len,
        )
        .map_err(|_| srs_opaque::error::InternalError::KsfError)?,
    );
    let mut output = Digest::default();
    argon2
        .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
        .map_err(|_| srs_opaque::error::InternalError::KsfError)?;
    Ok(output)
}

fn bearer_token(session_key: &str) -> String {
    format!("Bearer {}", session_key)
}

fn url(base_url: &str, endpoint: &str) -> String {
    if endpoint.starts_with("/") {
        format!("{}{}", base_url, endpoint)
    } else {
        format!("{}/{}", base_url, endpoint)
    }
}

fn register(
    base_url: &str,
    username: &str,
    password: &str,
    server_public_key: &PublicKey,
    ksf_params: &KsfParams,
) -> Result<()> {
    let payload = ksf_params.to_bytes()?;

    let rng = thread_rng();
    let mut registration_flow = ClientRegistrationFlow::new(
        username,
        password.as_bytes(),
        &server_public_key,
        &payload[..],
        Some(SERVER_IDENTITY),
        rng,
    );

    let registration_request = registration_flow.start();

    let request = serde_json::to_string(&RegisterStep1Request {
        username: registration_request.client_identity.clone(),
        blinded_element: registration_request.blinded_element,
    })?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(url(base_url, "api/accounts/register/step1"))
        .header(CONTENT_TYPE, "application/json")
        .body(request)
        .send()?
        .text()?;
    let response: RegisterStep1Response = serde_json::from_str(&resp[..]).unwrap();
    let session_id = response.session_id;
    let response = response.registration_response;

    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &ksf_params);
    let (registration_record, _) = registration_flow.finish(&response, ksf_stretch)?;

    let request2 = RegisterStep2Request {
        registration_record: RegistrationRecord {
            envelope: registration_record.envelope.clone(),
            masking_key: registration_record.masking_key,
            client_public_key: registration_record.client_public_key,
            payload,
        },
        session_id,
    };

    let request = serde_json::to_string(&request2)?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(url(base_url, "api/accounts/register/step2"))
        .header(CONTENT_TYPE, "application/json")
        .body(request)
        .send()?;
    if resp.status().is_success() {
        println!("success! user registered");
    } else {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
    }

    Ok(())
}

fn login(base_url: &str, username: &str, password: &str) -> Result<(String, AuthCode, Digest)> {
    let rng = thread_rng();
    let mut login_flow = ClientLoginFlow::new(username, password.as_bytes(), rng);

    let ke1 = login_flow.start()?;
    let request = AuthenticateStep1Request {
        username: username.to_owned(),
        key_exchange: ke1,
    };

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(url(base_url, "api/accounts/authenticate/step1"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&request)?)
        .send()?;
    if !resp.status().is_success() {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
        return Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: srs::error::ErrorCode::AuthenticationError,
            message: "Could not authenticate".to_owned(),
            source: None,
        });
    }

    let response: AuthenticateStep1Response = serde_json::from_str(&resp.text()?).unwrap();
    let ksf_params = KsfParams::from_bytes(&response.key_exchange.payload)?;
    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &ksf_params);
    let (ke3, session_key, export_key) = login_flow
        .finish(Some(SERVER_IDENTITY), &response.key_exchange, ksf_stretch)
        .map_err(|e| Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: ErrorCode::AuthenticationError,
            message: "Could not authenticate".to_owned(),
            source: Some(Source::OpaqueError(e)),
        })?;

    let request2 = AuthenticateStep2Request {
        session_id: response.session_id,
        key_exchange: ke3,
    };

    let request = serde_json::to_string(&request2)?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(url(base_url, "api/accounts/authenticate/step2"))
        .header(CONTENT_TYPE, "application/json")
        .body(request)
        .send()?;
    if !resp.status().is_success() {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
        return Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: srs::error::ErrorCode::AuthenticationError,
            message: "Could not authenticate".to_owned(),
            source: None,
        });
    }

    let response: AuthenticateStep2Response = serde_json::from_str(&resp.text()?).unwrap();
    println!("\nLogin successful");
    println!("\nSession key (short-lived session key to identify client at indexer):");
    println!("{}", response.session_key.as_str());
    println!("\nSession expiration (expiration date of the session):");
    println!("{}", response.session_expiration);
    println!(
        "\nOPAQUE session key (cryptographically strong random key to \
        encrypt traffic and guarantee forward secrecy):"
    );
    println!("{}", srs::util::b64_encode(&session_key[..]));
    println!(
        "\nOPAQUE export key: (cryptographically strong deterministic key \
        that client learns, is used for encryption):"
    );
    println!("{}\n", srs::util::b64_encode(&export_key[..]));

    Ok((response.session_key.to_str(), session_key, export_key))
}

fn logout(base_url: &str, session_key: &str) -> Result<()> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(url(base_url, "api/accounts/logout"))
        .header(AUTHORIZATION, bearer_token(session_key))
        .send()?;
    if !resp.status().is_success() {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
        return Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: srs::error::ErrorCode::AuthenticationError,
            message: "Could not logout".to_owned(),
            source: None,
        });
    }
    Ok(())
}

fn read_username_password() -> Result<(String, String)> {
    let mut username = String::new();
    print!("Username: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut username)?;

    let password = rpassword::prompt_password("Password: ").unwrap();
    Ok((
        username.trim_end().to_owned(),
        password.trim_end().to_owned(),
    ))
}

fn list_dbs(base_url: &str, session_key: &str) -> Result<()> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(url(base_url, "api/cipher-data"))
        .header(AUTHORIZATION, bearer_token(session_key))
        .send()?;
    if resp.status().is_success() {
        let response: GetChiperDbsResponse = resp.json()?;
        if response.results.is_empty() {
            println!("no databases yet");
        } else {
            for result in &response.results {
                println!(
                    "- ID {}: created_at: {} format: {}, application: {}",
                    result.id, result.created_at, result.format, result.application_id,
                );
            }
        }
    } else {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
    }
    Ok(())
}

fn download_db(base_url: &str, session_key: &str, id: i64) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(url(base_url, &format!("api/cipher-data/{}/download", id)))
        .header(AUTHORIZATION, bearer_token(session_key))
        .send()?;

    if !resp.status().is_success() {
        return Err(Error {
            message: format!(
                "[failure; {}] could not download DB: {}",
                resp.status(),
                resp.text()?
            ),
            ..Default::default()
        });
    }

    match resp.bytes() {
        Ok(bytes) => Ok(bytes.into()),
        Err(_) => Err(Error {
            message: format!("could not download database bytes"),
            ..Default::default()
        }),
    }
}

fn upload_db(base_url: &str, session_key: &str, encrypted_db: &[u8]) -> Result<()> {
    let part = multipart::Part::bytes(encrypted_db.to_vec());
    let form = multipart::Form::new().part("file", part);

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(url(
            base_url,
            "api/cipher-data?application_id=1&format=plain",
        ))
        .header(AUTHORIZATION, bearer_token(session_key))
        .multipart(form)
        .send()?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(Error {
            message: format!(
                "[failure; {}] could not upload DB: {}",
                resp.status(),
                resp.text()?
            ),
            ..Default::default()
        })
    }
}

fn encrypt(buf: &[u8], key: &Digest) -> Result<Vec<u8>> {
    let key = generate_encryption_key(key)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, buf).map_err(|_| Error {
        message: "could not encrypt data".to_owned(),
        ..Default::default()
    })?;
    Ok([&nonce[..], &ciphertext[..]].concat())
}

fn decrypt(buf: &[u8], key: &Digest) -> Result<Vec<u8>> {
    let key = generate_encryption_key(key)?;
    let cipher = AesGcm::<Aes256, NonceSize>::new(&key);

    let nonce_size = NonceSize::to_usize();
    if buf.len() < nonce_size {
        return Err(Error {
            message: "Malformed ciphertext, expected 96-bit nonce".to_owned(),
            ..Default::default()
        });
    }

    let mut nonce = GenericArray::<u8, typenum::U12>::default();
    nonce.copy_from_slice(&buf[0..nonce_size]);

    let plaintext = cipher
        .decrypt(&nonce, &buf[nonce_size..])
        .map_err(|_| Error {
            message: "could not decrypt data".to_owned(),
            ..Default::default()
        })?;

    Ok(plaintext)
}

fn generate_encryption_key(key: &Digest) -> Result<GenericArray<u8, U32>> {
    let kdf = primitives::extract_kdf(&[&key[..]])?;
    Ok(primitives::expand(&kdf, &[ENCRYPTION_KEY])?)
}

struct Login {
    username: String,
    session_key: String,
    #[allow(dead_code)]
    opaque_session_key: AuthCode,
    #[allow(dead_code)]
    opaque_export_key: Digest,
    encrypted_db: Option<Vec<u8>>,
}

struct Client {
    base_url: String,
    login: Option<Login>,
    ksf_params: KsfParams,
}

impl Client {
    fn new(base_url: String) -> Self {
        let ksf_params = KsfParams {
            m_cost: 8192,
            p_cost: 1,
            t_cost: 1,
            output_len: None,
        };
        Self {
            base_url,
            login: None,
            ksf_params,
        }
    }

    fn run(&mut self) -> Result<()> {
        println!("Demo client for SRS, enter 'help' to get started\n");
        loop {
            if let Some(login) = self.login.as_ref() {
                if let Some(_) = login.encrypted_db.as_ref() {
                    print!("[{}; db loaded] ", login.username);
                } else {
                    print!("[{}] ", login.username);
                }
            }
            print!("$> ");
            stdout().flush()?;

            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            let input = input.trim().split(" ").collect::<Vec<&str>>();
            if input.is_empty() {
                continue;
            }

            let command = input[0];
            let parameters = &input[1..];

            let result = match command {
                "register" => self.command_register(),
                "login" => self.command_login(),
                "logout" => self.command_logout(),
                "new-db" => self.command_new_db(),
                "list-dbs" => self.command_list_dbs(),
                "download-db" => self.command_download_db(parameters),
                "upload-db" => self.command_upload_db(),
                "edit-db" => self.command_edit_db(),
                "show-argon2" => self.command_show_argon2(),
                "configure-argon2" => self.command_configure_argon2(),
                "help" => self.command_help(),
                "exit" => break,
                "" => Ok(()),
                _ => {
                    println!("unknown command, use 'help' to list all commands");
                    Ok(())
                }
            };

            if let Err(err) = result {
                eprintln!("[{:?}] {}", err.code, err.message);
            }
            stdout().flush()?;
        }
        Ok(())
    }

    fn command_help(&self) -> Result<()> {
        println!("available commands:");
        println!("- register: register at SRS");
        println!("- login: login to SRS");
        println!("- logout: logout from SRS");
        println!("- new-db: create a new DB in memory");
        println!("- list-dbs: list all user's DBs");
        println!("- download-db $ID: download ciphertext $ID");
        println!("- upload-db: upload the encrypted database that's currently in memory");
        println!("- edit-db: decrypt the currently loaded DB, edit it, and encrypt it again");
        println!("- show-argon2: show current Argon2 KSF configuration");
        println!("- configure-argon2: configure Argon2 KSF");
        println!("- help: print this message");
        println!("- exit: exit the app");
        std::io::stdout().flush()?;
        Ok(())
    }

    fn command_register(&mut self) -> Result<()> {
        let (username, password) = read_username_password()?;
        let server_keypair = derive_keypair(b"foo", b"bar")?;
        register(
            &self.base_url,
            &username,
            &password,
            &server_keypair.public_key,
            &self.ksf_params,
        )?;
        self.login = None;
        Ok(())
    }

    fn command_login(&mut self) -> Result<()> {
        let (username, password) = read_username_password()?;
        let (session_id, session_key, export_key) = login(&self.base_url, &username, &password)?;
        self.login = Some(Login {
            username,
            session_key: session_id,
            opaque_session_key: session_key,
            opaque_export_key: export_key,
            encrypted_db: None,
        });
        Ok(())
    }

    fn command_logout(&mut self) -> Result<()> {
        if let Some(v) = self.login.as_ref() {
            match logout(&self.base_url, &v.session_key) {
                Ok(_) => println!("logged out successfully"),
                Err(err) => eprintln!("{}", err),
            };
            self.login = None;
        } else {
            println!("not logged in");
        }
        Ok(())
    }

    fn command_new_db(&mut self) -> Result<()> {
        if let Some(login) = self.login.as_mut() {
            login.encrypted_db = Some(vec![]);
        }
        self.command_edit_db()
    }

    fn command_list_dbs(&self) -> Result<()> {
        if let Some(login) = self.login.as_ref() {
            list_dbs(&self.base_url, &login.session_key)?;
        }
        Ok(())
    }

    fn command_download_db(&mut self, params: &[&str]) -> Result<()> {
        let id = params.first();
        if id.is_none() {
            eprintln!("ID expected");
        }

        let id = id.unwrap().parse::<i64>();
        if id.is_err() {
            eprintln!("could not parse ID {}", params[0]);
        }
        let id = id.unwrap();

        if let Some(login) = self.login.as_mut() {
            login.encrypted_db = Some(download_db(&self.base_url, &login.session_key, id)?);
        } else {
            eprintln!("not logged in");
        }
        Ok(())
    }

    fn command_upload_db(&self) -> Result<()> {
        if let Some((l, Some(db))) = self.login.as_ref().map(|l| (l, l.encrypted_db.as_ref())) {
            upload_db(&self.base_url, &l.session_key, db)?;
        } else {
            eprintln!("no database kept in memory");
        }
        Ok(())
    }

    fn command_edit_db(&mut self) -> Result<()> {
        if self.login.is_none() {
            eprintln!("not logged in");
            return Ok(());
        }
        let login = self.login.as_mut().unwrap();

        if login.encrypted_db.is_none() {
            eprintln!("no database loaded");
            return Ok(());
        }
        let db = login.encrypted_db.as_mut().unwrap();

        // attempt to decrypt the encrypted database
        let plaintext = if db.is_empty() {
            vec![]
        } else {
            decrypt(&db[..], &login.opaque_export_key)?
        };

        // write the plaintext database to a temporary textfile
        let mut tmpfile = NamedTempFile::new()?;
        tmpfile.write_all(&plaintext[..])?;
        tmpfile.flush()?;

        let (file, path) = tmpfile.keep().map_err(|_| Error {
            message: "could not create tmpfile".to_owned(),
            ..Default::default()
        })?;

        let path = path.to_str().ok_or_else(|| Error {
            message: "could not create tmpfile".to_owned(),
            ..Default::default()
        })?;

        // open the temporary file in an editor
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("vim {}", path))
            .spawn()
            .expect("Error: Failed to run editor")
            .wait()
            .expect("Error: Editor returned a non-zero status");

        // read the temporary file and delete it
        let unencrypted_db = std::fs::read(path)?;
        drop(file);
        std::fs::remove_file(path)?;

        // encrypt the data
        let encrypted_db = encrypt(&unencrypted_db, &login.opaque_export_key)?;
        self.login.as_mut().unwrap().encrypted_db = Some(encrypted_db);

        Ok(())
    }

    fn command_show_argon2(&self) -> Result<()> {
        println!("Current Argon2 configuration:");
        println!("- Memory (bytes): {}", self.ksf_params.m_cost);
        println!("- Iterations: {}", self.ksf_params.t_cost);
        println!("- Parallelism: {}", self.ksf_params.p_cost);
        Ok(())
    }

    fn command_configure_argon2(&mut self) -> Result<()> {
        fn read_u32(prompt: &str, default: u32) -> u32 {
            print!("{} [default {}]: ", prompt, default);
            std::io::stdout().flush().unwrap();
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer).expect("ok");
            if buffer.is_empty() {
                default
            } else {
                buffer.trim().parse().unwrap_or(default)
            }
        }

        println!("Configure and test Argon2 parameters");
        let m_cost = read_u32("Memory (bytes)", self.ksf_params.m_cost);
        let t_cost = read_u32("Iterations", self.ksf_params.t_cost);
        let p_cost = read_u32("Parallelism", self.ksf_params.p_cost);

        let config = KsfParams {
            m_cost,
            t_cost,
            p_cost,
            output_len: None,
        };

        println!("\nTesting Argon2 configuration {}", config);
        let start = Instant::now();
        argon2_stretch(&[0, 0, 0], &config)?;
        let duration = start.elapsed();
        println!("Computing Argon2 took {:?}", duration);

        self.ksf_params = config;

        Ok(())
    }
}

fn main() -> Result<()> {
    let base_url = "http://localhost:8080".to_owned();
    Client::new(base_url).run()
}
