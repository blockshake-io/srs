pub const NS_SESSION: &str = "session:";
pub const NS_PENDING_LOGIN: &str = "pending_login:";
pub const NS_PENDING_REGISTRATION: &str = "pending_registration:";
pub const NS_RATE_LIMIT: &str = "rl:";

pub(crate) trait ToRedisKey {
    fn to_redis_key(&self, prefix: &str) -> String;
}

impl ToRedisKey for str {
    fn to_redis_key(&self, prefix: &str) -> String {
        format!("{}:{}", prefix, self)
    }
}

impl ToRedisKey for String {
    fn to_redis_key(&self, prefix: &str) -> String {
        format!("{}:{}", prefix, &self)
    }
}
