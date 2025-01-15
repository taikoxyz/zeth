use lazy_static::lazy_static;
use redis::{RedisError, RedisResult};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type SingleStorage = Arc<Mutex<HashMap<Value, Value>>>;
type GlobalStorage = Mutex<HashMap<String, SingleStorage>>;

lazy_static! {
    // #{redis_url => single_storage}
    //
    // We use redis_url to distinguish different redis database for tests, to prevent
    // data race problem when running multiple tests.
    static ref GLOBAL_STORAGE: GlobalStorage = Mutex::new(HashMap::new());
}

pub struct MockRedisConnection {
    storage: SingleStorage,
}

impl MockRedisConnection {
    pub(crate) fn new(redis_url: String) -> Self {
        let mut global = GLOBAL_STORAGE.lock().unwrap();
        Self {
            storage: global
                .entry(redis_url)
                .or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
                .clone(),
        }
    }

    pub fn set_ex<K: Serialize, V: Serialize>(
        &mut self,
        key: K,
        val: V,
        _ttl: u64,
    ) -> RedisResult<()> {
        let mut lock = self.storage.lock().unwrap();
        lock.insert(json!(key), json!(val));
        Ok(())
    }

    pub fn get<K: Serialize, V: serde::de::DeserializeOwned>(&mut self, key: &K) -> RedisResult<V> {
        let lock = self.storage.lock().unwrap();
        match lock.get(&json!(key)) {
            None => Err(RedisError::from((redis::ErrorKind::TypeError, "not found"))),
            Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
                RedisError::from((
                    redis::ErrorKind::TypeError,
                    "deserialization error",
                    e.to_string(),
                ))
            }),
        }
    }

    pub fn del<K: Serialize>(&mut self, key: K) -> RedisResult<usize> {
        let mut lock = self.storage.lock().unwrap();
        if lock.remove(&json!(key)).is_none() {
            Ok(0)
        } else {
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use redis::RedisResult;

    use crate::{Pool, RedisPoolConfig};

    #[test]
    fn test_mock_redis_pool() {
        let config = RedisPoolConfig {
            redis_ttl: 111,
            redis_url: "redis://localhost:6379".to_string(),
        };
        let mut pool = Pool::open(config).unwrap();
        let mut conn = pool.conn().expect("mock conn");

        let key = "hello".to_string();
        let val = "world".to_string();
        conn.set_ex(key.clone(), val.clone(), 111)
            .expect("mock set_ex");

        let actual: RedisResult<String> = conn.get(&key);
        assert_eq!(actual, Ok(val));

        let _ = conn.del(&key);
        let actual: RedisResult<String> = conn.get(&key);
        assert!(actual.is_err());
    }

    #[test]
    fn test_mock_multiple_redis_pool() {
        let mut pool1 = Pool::open(RedisPoolConfig {
            redis_ttl: 111,
            redis_url: "redis://localhost:6379".to_string(),
        })
        .unwrap();
        let mut pool2 = Pool::open(RedisPoolConfig {
            redis_ttl: 111,
            redis_url: "redis://localhost:6380".to_string(),
        })
        .unwrap();

        let mut conn1 = pool1.conn().expect("mock conn");
        let mut conn2 = pool2.conn().expect("mock conn");

        let key = "hello".to_string();
        let world = "world".to_string();

        {
            conn1
                .set_ex(key.clone(), world.clone(), 111)
                .expect("mock set_ex");
            let actual: RedisResult<String> = conn1.get(&key);
            assert_eq!(actual, Ok(world.clone()));
        }

        {
            let actual: RedisResult<String> = conn2.get(&key);
            assert!(actual.is_err());
        }

        {
            let meme = "meme".to_string();
            conn2
                .set_ex(key.clone(), meme.clone(), 111)
                .expect("mock set_ex");
            let actual: RedisResult<String> = conn2.get(&key);
            assert_eq!(actual, Ok(meme));
        }

        {
            let actual: RedisResult<String> = conn1.get(&key);
            assert_eq!(actual, Ok(world));
        }
    }
}
