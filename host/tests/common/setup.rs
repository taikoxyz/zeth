use crate::common::Client;
use crate::common::{TestServerBuilder, TestServerHandle};
use rand::Rng;

pub const REDIS_URL_PREFIX: &str = "redis://localhost:6379/";

// TODO: make sure redis is not used by other tests
pub async fn setup() -> (TestServerHandle, Client) {
    let port = rand::thread_rng().gen_range(1024..65535);
    let redis_database = port % 15; // port is randomly generated, so it can be used as redis database
    let server = TestServerBuilder::default()
        .port(port)
        .redis_url(format!("{REDIS_URL_PREFIX}{redis_database}"))
        .build();
    let client = server.get_client();

    // Wait for the server to be ready
    let mut last_log_time = std::time::Instant::now();
    loop {
        match client.get("/v2/health").await {
            Ok(_) => {
                break;
            }
            Err(error) => {
                if last_log_time.elapsed().as_secs() > 2 {
                    println!("Waiting for server to be ready..., response: {error:?}");
                    last_log_time = std::time::Instant::now();
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }

    return (server, client);
}
