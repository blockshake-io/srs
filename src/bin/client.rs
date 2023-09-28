use rand::thread_rng;
use srs_indexer::{
    error::{Cause, ErrorCode},
    handlers::{
        login::{LoginStep1Request, LoginStep1Response, LoginStep2Request, LoginStep2Response},
        registration::{RegisterStep1Request, RegisterStep1Response, RegisterStep2Request},
    },
    Error, KsfParams, Result,
};
use srs_opaque::{
    ciphersuite::Digest,
    keypair::PublicKey,
    messages::RegistrationRecord,
    opaque::{ClientLoginFlow, ClientRegistrationFlow},
    primitives::derive_keypair,
};
use std::{env, io::Write};

const SERVER_IDENTITY: &str = "srs.blockshake.io";

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

fn register(username: &str, password: &str, server_public_key: &PublicKey) -> Result<()> {
    let payload = KsfParams {
        m_cost: 8192,
        p_cost: 1,
        t_cost: 1,
        output_len: None,
    };

    let rng = thread_rng();
    let mut registration_flow = ClientRegistrationFlow::new(
        username,
        password.as_bytes(),
        &server_public_key,
        &payload,
        Some(SERVER_IDENTITY),
        rng,
    );

    let registration_request = registration_flow.start();

    println!("[PHASE 1] connecting to server");
    let request = serde_json::to_string(&RegisterStep1Request {
        username: registration_request.client_identity.clone(),
        blinded_element: registration_request.blinded_element,
    })?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("http://localhost:8080/api/register/step1")
        .header("Content-Type", "application/json")
        .body(request)
        .send()?
        .text()?;
    let response: RegisterStep1Response = serde_json::from_str(&resp[..]).unwrap();
    let session_id = response.session_id;
    let response = response.registration_response;
    println!("obtained evaluated element, finalizing...");

    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &payload);
    let (registration_record, _) = registration_flow.finish(&response, ksf_stretch)?;

    let request2 = RegisterStep2Request {
        registration_record: RegistrationRecord {
            envelope: registration_record.envelope.clone(),
            masking_key: registration_record.masking_key,
            client_public_key: registration_record.client_public_key,
            payload: payload,
        },
        session_id,
    };

    println!("[PHASE 2] connecting to server");
    let request = serde_json::to_string(&request2)?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("http://localhost:8080/api/register/step2")
        .header("Content-Type", "application/json")
        .body(request)
        .send()?;
    if resp.status().is_success() {
        println!("success! user registered");
    } else {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
    }

    Ok(())
}

fn login(username: &str, password: &str) -> Result<()> {
    let rng = thread_rng();
    let mut login_flow = ClientLoginFlow::new(username, password.as_bytes(), rng);

    let ke1 = login_flow.start()?;
    let request = LoginStep1Request {
        username: username.to_owned(),
        key_exchange: ke1,
    };

    println!("[PHASE 1] connecting to server");
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("http://localhost:8080/api/login/step1")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()?;
    if !resp.status().is_success() {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
        return Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: srs_indexer::error::ErrorCode::AuthenticationError,
            message: "Could not authenticate".to_owned(),
            cause: None,
        });
    }

    let response: LoginStep1Response = serde_json::from_str(&resp.text()?).unwrap();
    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &response.key_exchange.payload);
    let (ke3, _session_key, _export_key) = login_flow
        .finish(Some(SERVER_IDENTITY), &response.key_exchange, ksf_stretch)
        .map_err(|e| Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: ErrorCode::AuthenticationError,
            message: "Could not authenticate".to_owned(),
            cause: Some(Cause::OpaqueError(e)),
        })?;

    let request2 = LoginStep2Request {
        session_id: response.session_id,
        key_exchange: ke3,
    };

    println!("[PHASE 2] connecting to server");
    let request = serde_json::to_string(&request2)?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("http://localhost:8080/api/login/step2")
        .header("Content-Type", "application/json")
        .body(request)
        .send()?;
    if !resp.status().is_success() {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
        return Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: srs_indexer::error::ErrorCode::AuthenticationError,
            message: "Could not authenticate".to_owned(),
            cause: None,
        });
    }

    let response: LoginStep2Response = serde_json::from_str(&resp.text()?).unwrap();
    println!("Login successful");
    println!("session key: {}", response.session_key.as_str());
    println!("session expiration: {}", response.session_expiration);

    println!("[PHASE 3] testing login");
    let request = serde_json::to_string(&request2)?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("http://localhost:8080/api/login/test")
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!("Bearer {}", response.session_key.as_str()),
        )
        .body(request)
        .send()?;
    if resp.status().is_success() {
        println!("authentication test successful");
    } else {
        println!("[failure; {}] {}", resp.status(), resp.text()?);
    }

    Ok(())
}

fn read_username_password() -> Result<(String, String)> {
    let mut username = String::new();
    let mut password = String::new();

    print!("Username: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut username)?;

    print!("Password (not hidden): ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut password)?;
    Ok((
        username.trim_end().to_owned(),
        password.trim_end().to_owned(),
    ))
}

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();
    let cmd = match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("expecting a command (register or login)");
            std::process::exit(-1);
        }
    };

    match &cmd[..] {
        "register" => {
            let (username, password) = read_username_password()?;
            // TODO: drop key-derivation and read public-key from somewhere
            let server_keypair = derive_keypair(b"foo", b"bar")?;
            register(&username, &password, &server_keypair.public_key)?;
        }
        "login" => {
            let (username, password) = read_username_password()?;
            login(&username, &password)?;
        }
        _ => {
            eprintln!("unknown command `{}`", cmd);
            std::process::exit(-1);
        }
    }

    Ok(())
}
