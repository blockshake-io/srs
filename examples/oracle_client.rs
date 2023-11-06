use blstrs::{Compress, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use sha2::{Digest, Sha512_256};
use srs::http::indexer::blind_evaluate::{BlindEvaluateRequest, EvaluatedElement};
use srs_opaque::ciphersuite::DST;

struct BlindResult {
    blind: Scalar,
    blinded_element: G2Affine,
}

fn blind(private_input: &[u8]) -> BlindResult {
    let blind = Scalar::random(rand::thread_rng());
    let element = G2Projective::hash_to_curve(private_input, DST, &[]);
    let blinded_element = G2Affine::from(element * blind);

    BlindResult {
        blind,
        blinded_element,
    }
}

fn finalize(blind_result: &BlindResult, evaluated_element: &Gt) -> [u8; 32] {
    let y = evaluated_element * blind_result.blind.invert().unwrap();

    let mut bytes = Vec::new();
    y.write_compressed(&mut bytes).unwrap();
    let hash: [u8; 32] = Sha512_256::digest(bytes)
        .as_slice()
        .try_into()
        .expect("Wrong length");
    hash
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_input = "test";
    let private_input = "password";
    let blind_result = blind(private_input.as_bytes());

    println!("selected blinding_key: {}", blind_result.blind);
    println!("blinded element: {}", blind_result.blinded_element);

    println!("connecting to server");
    let host = "http://localhost:8080";

    let request = BlindEvaluateRequest {
        blinded_element: blind_result.blinded_element,
        public_input: public_input.to_owned(),
        key_version: None,
    };

    let resp = reqwest::blocking::Client::new()
        .post(format!("{}/api/oprf/blind-evaluate", host))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()?;

    if resp.status().is_success() {
        let resp = resp.text()?;
        let response: EvaluatedElement = serde_json::from_str(&resp[..])?;
        println!("obtained evaluated element, finalizing...");

        let hash = finalize(&blind_result, &response.evaluated_element);
        let mut hash_str = String::with_capacity(2 * hash.len());
        use core::fmt::Write;
        for byte in hash {
            write!(hash_str, "{:02X}", byte)?;
        }
        println!("OPRF output: {}", hash_str);
    } else {
        println!("[error] status: {}", resp.status());
        println!("response: {}", resp.text()?);
    }

    Ok(())
}
