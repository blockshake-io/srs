use std::time::{SystemTime, UNIX_EPOCH};

use redis::{Commands, FromRedisValue, ToRedisArgs};
use serde::{Deserialize, Serialize};

use crate::{
    redis::{ToRedisKey, NS_RATE_LIMIT},
    Result,
};

/// We allow 5 trials per minute
const MAX_BUCKET_SIZE: f64 = 5.0;

/// The refill rate denotes how many tokens are added to the bucket every second.
/// We add a token every 12 seconds, which that means every second one-twelfth of
/// a token is added to the bucket.
const REFILL_RATE: f64 = 1.0 / 12.0;

/// The number of nanoseconds in one second
const NS_SCALING: f64 = 1e9;

#[derive(Debug, Serialize, Deserialize)]
struct TokenBucket {
    #[serde(rename = "bs")]
    bucket_size: f64,
    #[serde(rename = "lrt")]
    last_refill_timestamp: u128,
}

impl TokenBucket {
    fn new(now: u128) -> Self {
        Self {
            bucket_size: MAX_BUCKET_SIZE,
            last_refill_timestamp: now,
        }
    }

    fn is_allowed(&mut self, now: u128) -> bool {
        self.refill(now);
        if self.bucket_size >= 1.0 {
            self.bucket_size -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: u128) {
        if now < self.last_refill_timestamp {
            panic!("[TokenBucket] clock jumped back in time");
        }
        let time_diff = (now - self.last_refill_timestamp) as f64;
        let tokens_to_add = time_diff * REFILL_RATE / NS_SCALING;
        self.bucket_size = f64::min(self.bucket_size + tokens_to_add, MAX_BUCKET_SIZE);
        self.last_refill_timestamp = now;
    }

    fn seconds_until_full(&self, now: u128) -> usize {
        if now < self.last_refill_timestamp {
            panic!("[TokenBucket] clock jumped back in time");
        }
        let missing_tokens = MAX_BUCKET_SIZE - self.bucket_size;
        let elpased_ns = (now - self.last_refill_timestamp) as f64;
        let missing_seconds = (missing_tokens / REFILL_RATE) - (elpased_ns / NS_SCALING);
        f64::max(0.0, missing_seconds.ceil()) as usize
    }
}

impl FromRedisValue for TokenBucket {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let v: String = String::from_redis_value(v)?;
        serde_json::from_str(&v[..]).map_err(|e| e.into())
    }
}

impl ToRedisArgs for TokenBucket {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + redis::RedisWrite,
    {
        let json = serde_json::to_string(&self).expect("token_bucket can be json-serialized");
        out.write_arg(json.as_bytes())
    }
}

fn current_unix_time_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("timestamp before unix epoch")
        .as_nanos()
}

pub fn check_rate_limit(conn: &mut redis::Connection, username: &str) -> Result<()> {
    // get a TokenBucket from redis or create a new full one if it doesn't exist
    let redis_key = username.to_redis_key(NS_RATE_LIMIT);
    let now = current_unix_time_ns();
    let mut token_bucket = conn
        .get(&redis_key[..])
        .unwrap_or_else(|_| TokenBucket::new(now));

    // check if a request is allowed
    let is_allowed = token_bucket.is_allowed(now);

    // update the TokenBucket in Redis. the bucket's expiry time is set to the
    // time when the bucket becomes full again. This way, rate-limiting records
    // do not accumulate in Redis
    conn.set_ex(
        &redis_key[..],
        &token_bucket,
        token_bucket.seconds_until_full(now),
    )?;

    match is_allowed {
        true => Ok(()),
        false => Err(crate::Error {
            status: actix_web::http::StatusCode::TOO_MANY_REQUESTS.as_u16(),
            code: crate::error::ErrorCode::RateLimitExceededError,
            message: "rate limit exceeded".to_owned(),
            cause: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use crate::rate_limiter::{TokenBucket, MAX_BUCKET_SIZE};
    const ONE_NS: u128 = 1_000_000_000;

    fn ns(t: u128) -> u128 {
        t * ONE_NS
    }

    #[test]
    fn new_bucket_is_full() {
        let bucket = TokenBucket::new(0);
        assert_eq!(bucket.bucket_size, MAX_BUCKET_SIZE);
    }

    #[test]
    fn refilling_full_bucket_is_noop() {
        let now = 0;
        let mut bucket = TokenBucket::new(now);
        bucket.refill(now);
        assert_eq!(bucket.bucket_size, MAX_BUCKET_SIZE);
    }

    #[test]
    fn rate_limiting_kicks_in() {
        let now = 0;
        let mut bucket = TokenBucket::new(now);
        // one can try five times before being rate limited
        for _ in 0..5 {
            assert!(bucket.is_allowed(now));
        }
        // trying a sixth time is disallowed
        assert!(!bucket.is_allowed(now));
    }

    #[test]
    fn rate_limiting_opens_again() {
        // we create a bucket that's completely drained at time t=0
        let mut bucket = TokenBucket {
            bucket_size: 0_f64,
            last_refill_timestamp: 0,
        };
        // the bucket is closed for the next 11 seconds
        assert!(!bucket.is_allowed(ns(0)));
        assert!(!bucket.is_allowed(ns(11)));
        // the bucket regains one token after 12 seconds
        assert!(bucket.is_allowed(ns(12)));
    }

    #[test]
    fn bucket_size_does_not_grow_beyond_maximum() {
        // we create a bucket that's completely drained at time t=0
        let mut bucket = TokenBucket {
            bucket_size: 0_f64,
            last_refill_timestamp: 0,
        };
        // for the next 60 seconds one token is added every 12 seconds
        for i in 0..5 {
            bucket.refill(ns(i * 12));
            assert_eq!(bucket.bucket_size, i as f64);
        }
        // afterwards, no more tokens are added
        bucket.refill(ns(72));
        assert_eq!(bucket.bucket_size, MAX_BUCKET_SIZE);
    }

    #[test]
    fn test_seconds_until_full() {
        // we create a bucket that's completely drained at time t=0.
        // at that point, it takes 60 seconds to replenish
        let mut bucket = TokenBucket {
            bucket_size: 0_f64,
            last_refill_timestamp: 0,
        };
        assert_eq!(bucket.seconds_until_full(ns(0)), 60);
        // if we look at the bucket at time t=15, it takes 45 seconds
        // until it is full
        assert_eq!(bucket.seconds_until_full(ns(15)), 45);

        // after 12 seconds we regain a token
        bucket.refill(ns(12));
        assert_eq!(bucket.seconds_until_full(ns(12)), 48);
        assert_eq!(bucket.seconds_until_full(ns(15)), 45);

        // after 60 seconds the bucket is full
        bucket.refill(ns(60));
        assert_eq!(bucket.seconds_until_full(ns(60)), 0);
        assert_eq!(bucket.seconds_until_full(ns(80)), 0);
    }

    #[test]
    #[should_panic]
    fn non_linear_clock_panics() {
        // we create a bucket at time 36
        let mut bucket = TokenBucket {
            bucket_size: 3_f64,
            last_refill_timestamp: ns(36),
        };
        // we refill the bucket at time 0, which panics
        bucket.refill(ns(0));
    }
}
