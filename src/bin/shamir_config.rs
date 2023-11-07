use std::env::{self, Args};

use srs_opaque::{serialization::b64_scalar, shamir};

fn take_u64(args: &mut Args) -> Result<u64, String> {
    match args.next() {
        Some(v) => v
            .parse()
            .map_err(|_| format!("could not parse {} as u64", v)),
        None => Err("expected integer, found none".to_owned()),
    }
}

fn main() -> Result<(), String> {
    println!("
    *****************************************
    *** WARNING: do not use in production ***
    *****************************************
    ");

    let mut args = env::args();
    args.next().expect("program name");
    let threshold = take_u64(&mut args)?;
    let nr_shares = take_u64(&mut args)?;

    if threshold > nr_shares {
        return Err(format!(
            "treshold {} must be <= number shares {}",
            threshold, nr_shares
        ));
    }

    println!("threshold: {}", threshold);
    println!("number shares: {}", nr_shares);
    println!();

    let (_, shares) =
        shamir::generate_secrets(threshold, nr_shares).map_err(|_| "could not generate secrets")?;

    for (i, share) in shares.iter().enumerate() {
        let index = i + 1;
        let share = b64_scalar::encode(share);
        println!("Index {}, secret: {}", index, share);
    }

    Ok(())
}
