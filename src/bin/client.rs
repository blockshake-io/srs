use rand::thread_rng;
use srs_indexer::{
    handlers::registration::{RegisterStep1Response, RegisterStep2Request},
    util, KsfParams, Result,
};
use srs_opaque::{
    ciphersuite::Digest, messages::RegistrationResponse, opaque::ClientRegistrationFlow,
    primitives::derive_keypair,
};

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

fn register(username: &str, password: &str) -> Result<()> {
    let server_keypair = derive_keypair(b"secret seed", b"public info")?;
    let server_public_key = server_keypair.public_key.clone();
    let server_identity = Some("srs.blockshake.io");

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
        server_identity,
        rng,
    );

    let registration_request = registration_flow.start();
    let blinded_element_b64 =
        util::b64_encode(&registration_request.blinded_element.to_compressed());

    println!("[PHASE 1] connecting to server");
    let host = "http://localhost:8080";
    let url = format!(
        "{}/api/register/step1?username={}&blinded_element={}",
        host, registration_request.client_identity, blinded_element_b64
    );

    let resp = reqwest::blocking::get(url)?.text()?;
    let response: RegisterStep1Response = serde_json::from_str(&resp[..]).unwrap();
    let session_id = response.session_id;
    let response = RegistrationResponse {
        evaluated_element: response.evaluated_element,
        server_public_key: response.server_public_key,
    };
    println!("obtained evaluated element, finalizing...");

    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &payload);
    let (registration_record, _) = registration_flow.finish(&response, ksf_stretch)?;

    let request2 = RegisterStep2Request {
        envelope: registration_record.envelope.clone(),
        masking_key: registration_record.masking_key,
        client_public_key: registration_record.client_public_key,
        payload: payload,
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

fn main() -> Result<()> {
    let username = "foo";
    let password = "bar";
    register(username, password)?;

    Ok(())
}
