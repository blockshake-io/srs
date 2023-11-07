# Secrets Recovery Service (SRS)

SRS is a protocol to securely encrypt client-side secrets, store them on SRS
servers, and later recover them when necessary.

- talk about use case: crypto wallets

A more comprehensive description of SRS can be found in our [whitepaper][1].

## Cryptographic Underpinnings

SRS relies on several state-of-the-art cryptographic protocols, [Argon2](5),
[OPRF](3), and [OPAQUE](4), to provide best-in-class security.

### Argon2

[Argon2](5) is a key-stretching function (KSF) that is designed to be slow and
resource-intensive to make it slow and expensive for attackers to compute a
large number of hash values. To control Argon2’s resource-usage, it is
parameterized by the number of iterations that it performs (controlling CPU
cost), the amount of memory it uses (controlling space usage), and the level of
parallelism it is allowed to use. Argon2 is the winner of the Password Hashing
Competition and recommended by [OWASP](6).

We use Argon2 client-side during password authentication to harden a derived
cryptographic key and make brute-force attacks expensive.

### OPRF

[OPRF](3) is a protocol to securely compute a pseudorandom function $H_s(p,i)$
between a client that knows the inputs to the function $p$ and $i$, and a server
that holds a secret key $s$. The inputs to the function, $p$ and $i$, are called
the *private input* and the *public input*, respectively. The protocol
guarantees that after it runs to completion:

- The client learns the output of the function but nothing else (in particular not
  the secret key $s$).
- The server learns the public input but nothing else (neither the private input $p$
  nor the output).
- An outside observer can only observe the public input, but learns nothing else.

In a nutshell, we use the OPRF protocol harden the user's password with the
server-side secret key $s$. That is, using OPRF we turn a user's password into a
high-entropy, cryptographic key that can be used to encrypt the user's secrets.
In this case, the private input $p$ represents the user's password and the
public input $i$ is the user's username (e.g., email address, etc.).  The public
input $i$ is used for rate-limiting to defend against brute-force guessing
attacks.

### OPAQUE

[OPAQUE](4) is a protocol for secure password-based authentication without
reavling the passphrase to anyone. Password authentication is the most commonly
used authentication mechanism that exists today, but the way it is traditionally
implemented sends the user's passphrase in cleartext to the server. This makes
the passphrase vulnerable to mishandling on the server’s side, e.g., by
inadvertently logging all passphrases or storing them in plaintext.

## Architecture

**TODO**


## Building

SRS is written in Rust and requires an up-to-date [Rust compiler][2] that
compiles Rust version 1.68.2 or newer. Use `cargo` to download all necessary
dependencies and compile the code (drop the `--release` flag if you want to
compile a debug build):

```sh
cargo build --release
```

The compiled artifacts can be found in the folder `./target/release` (or
`./target/debug` for a debug build). Two binaries are generated:
- `indexer_server`
- `oracle_server`

In addition, the repository contains two examples in the `./examples` folder
that demonstrate how to intereact with the indexer & oracle servers. They can be
compiled as follows:

```sh
cargo build --examples
```


## Running SRS Servers

SRS servers require access to the following services:
- PostgreSQL: used by the indexer server to store user-related data
- Redis: used by the indexer and oracle servers for rate limiting and session management

In the following we assume that those external services have been set up and you
have the necessary credentials to access them.

### Oracle Server

#### Configuration

The following *environment variables* need to be set for an oracle server:
- `SRV_ADDRESS`: This is the address that the server binds to (e.g., `127.0.0.1` or `localhost`)
- `SRV_PORT`: This is the port that the server binds to (e.g., `8081`)
- `SRV_SECRET_KEYS`: This represents the OPRF key material(s) that the server uses,
   explained in detail below.
- `SRV_DEFAULT_KEY_VERSION`: This is an integer that denotes which OPRF key to use
- `REDIS_CONNECTION_STRING`: This is the connection string that allows the server to
   access a redis instance

Environment variable `SRV_SECRET_KEYS` is a string that encodes one ore more
OPRF key shares. We use [Shamir's Secret Sharing (SSS)](#shamirs-secret-sharing)
to split up the OPRF key across a number of oracle servers. Each key share has
an `index` that represents the $x$-coordinate of the point and a `share` that
represents its $y$-coordinate (see [here](#shamirs-secret-sharing) for details).
In addition, secret OPRF keys are versioned and an oracle server supports
multiple such keys in order to support, e.g., key rotations. `SRV_SECRET_KEYS`
is a string-representation of a JSON array that looks like this:

```json
[
    {
        "version": 1,
        "index": 1,
        "share": "ICnhAK5Gokxz2NYIynPDFj9hpmC0zJ4Kr5rPD6ce58w"
    }
]
```

Key `SRV_DEFAULT_KEY_VERSION` points to one of the keys in `SRV_SECRET_KEYS`
that is considered the default key if a user doesn't specify a key version in
requests. This is typically the most recent key.

How to configure the environment variables depends on your system, for example
many cloud providers have a dedicated GUI to set them up. During development, it
is convenient to store these values in an `.env` file and load them into the
shell. An example `.env` file is shown in `.oracle.env` and it can be loaded
(depending on your shell) by calling `source .oracle.env`.

#### Executing Oracle Server

Once compiled in release mode and configured, an oracle can be executed by
calling:

```sh
./target/release/oracle_server
```

During development it is more convenient to use the following to compile &
execute an oracle server:

```sh
cargo run --bin oracle_server
```

### Indexer Server

#### Configuration

The following *environment variables* need to be set for an indexer server:
- `SRV_ADDRESS`: This is the address that the server binds to (e.g., `127.0.0.1` or `localhost`)
- `SRV_PORT`: This is the port that the server binds to (e.g., `8081`)
- `SRV_SECRET_KEYS`: This represents the OPRF key material(s) that the server uses,
   explained in detail below.
- `SRV_DEFAULT_KEY_VERSION`: This is an integer that denotes which OPRF key to use
- `REDIS_CONNECTION_STRING`: This is the connection string that allows the server to
   access a redis instance


## Running SRS

The following *environment variables* need to be set for an indexer server:
- `SRV_ADDRESS`: This is the address that the server binds to (e.g., `127.0.0.1` or `localhost`)
- `SRV_PORT`: This is the port that the server binds to (e.g., `8081`)
- `SRV_KE_SEED`: This is the seed that derives the key pair used in OPAQUE's key exchange
- `SRV_KE_INFO`: This is the info string that is used to derive the key pair used
   in OPAQUE's key exchange
- `SRV_IDENTITY`: The name of the server (e.g., `srs.blockshake.io`)
- `SRV_OPRF_HOSTS`: This is a whitespace separated list of hosts that run oracle servers
  (e.g., `"http://localhost:8081 http://localhost:8082 http://localhost:8083"`)
- `SRV_OPRF_THRESHOLD`: This denotes the threshold of Oracle servers that need to be
  available to perform Shamir's secret sharing.
- `SRV_USERNAME_OPRF_KEY`: This is a base64-encoded scalar in BLS12-381 that is used
  to blind usernames before they are sent to oracle servers
- `SRV_DEFAULT_KEY_VERSION`: This is the OPRF key version to use by default
- `SRV_FAKE_KSF_PARAMS`: This is a string (e.g., `"[{\"m_cost\": 8192, \"t_cost\": 1, \"p_cost\": 1}]"`)
  that denotes a list of KSF (e.g., Argon2) parameters that are used for fake records
  when someone tries to login with a username that does not exist
- `DB_USER`: This is the username used to connect to postgres
- `DB_PASSWORD`: This is the password used to connect to postgres
- `DB_HOST`: This is the host of the postgres server
- `DB_NAME`: This is the name of the database
- `REDIS_CONNECTION_STRING`: This is the connection string that allows the server to
   access a redis instance

Like with the oracle server, an example `.env` file that contains these environment
variables can be found in the file `.indexer.env`.

#### Executing Oracle Server

Once compiled in release mode and configured, an indexer can be executed by
calling:

```sh
./target/release/indexer_server
```

During development it is more convenient to use the following to compile &
execute an indexer server:

```sh
cargo run --bin indexer_server
```

## Shamir's Secret Sharing

We use Shamir's Secret Sharing (SSS) scheme to split up a secret key across a
number $n$ of oracle servers such that a threshold $t$, $1 < t \leq n$, of
oracles is required to re-assemble the secret. SSS improves (a) the security of
SRS because it can sustain the leakage of up to $t-1$ key shares without
compromising security and (b) the availability of SRS because it can sustain
$n-t$ oracle outages and still be able to recover the OPRF key.

The $n$ key shares are points on a randomly generated polynomial, hence each key
share consists of two values corresponding to the $x$- and $y$-coordinates of
that point. The $x$-coordinate is typically a small an integer, e.g., 1, 2, etc.
and in our case the $y$-coordinate represents a scalar in the BLS12-381 scalar
field (these are large, 32-byte integers). The basic idea of SSS is that with
$t$ points on a curve you can uniquely describe a degree $t-1$ polynomial, yet
if you have fewer than $t$ points there is no way to find this polynomial other
than brute-force guessing. To recover the secret key, one gathers $t$ points,
re-constructs the polynomial, and evaluates the polynomial at a pre-specified
index (typically 0).

There are multiple ways to generate a SSS polynomial. In production, it is
recommended to use a ceremony to generate the OPRF key shares such that they
never leave an oracle. During development, holding such a ceremony is
cumbersome, hence we provide a simple tool to generate the OPRF key shares on a
single machine:

```
cargo run --bin shamir_config $treshold $number_shares
```

where, `$threshold` is the number of oracle servers that are needed to evaluate
OPRF and `$number_shares` is the total number of oracle servers.

[1]: https://blockshake.substack.com/p/srs-whitepaper
[2]: https://www.rust-lang.org/tools/install
[3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html
[4]: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-11.html
[5]: https://www.rfc-editor.org/rfc/rfc9106.html
[6]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id