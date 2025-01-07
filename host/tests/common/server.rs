use crate::common::Client;
use raiko_host::{server::serve, Opts, ProverState};
use rand::Rng;
use tokio_util::sync::CancellationToken;

/// Builder for a test server.
///
/// This builder only supports setting a few parameters for testing.
///
/// Examples:
/// ```
/// let server = TestServerBuilder::default()
///     .port(8080)
///     .redis_url("redis://127.0.0.1:6379/0".to_string())
///     .build();
/// ```
#[derive(Default, Debug)]
pub struct TestServerBuilder {
    port: Option<u16>,
    redis_url: Option<String>,
}

impl TestServerBuilder {
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn redis_url(mut self, redis_url: String) -> Self {
        self.redis_url = Some(redis_url);
        self
    }

    pub fn build(self) -> TestServerHandle {
        let port = self
            .port
            .unwrap_or(rand::thread_rng().gen_range(1024..65535));
        let address = format!("127.0.0.1:{port}");
        let redis_url = self
            .redis_url
            .unwrap_or("redis://localhost:6379/0".to_string());

        // TODO
        // opts.config_path
        // opts.chain_spec_path
        let log_level = std::env::var("RUST_LOG").unwrap_or("info".to_string());
        let opts = Opts {
            address,
            log_level,

            redis_url,
            concurrency_limit: 16,
            redis_ttl: 3600,
            ..Default::default()
        };
        let state = ProverState::init_with_opts(opts).expect("Failed to initialize prover state");
        let token = CancellationToken::new();

        // Run the server in a separate thread with the ability to cancel it when our testing is done.
        let (state_, token_) = (state.clone(), token.clone());
        tokio::spawn(async move {
            println!("Starting server on port {}", port);
            tokio::select! {
                _ = token_.cancelled() => {
                    println!("Test done");
                }
                result = serve(state_) => {
                    match result {
                        Ok(()) => {
                            assert!(false, "Unexpected server shutdown");
                        }
                        Err(error) => {
                            assert!(false, "Server failed due to: {error:?}");
                        }
                    };
                }
            }
        });

        TestServerHandle {
            state,
            _token: token,
        }
    }
}

/// Handle for a test server.
///
/// Note that we don't need to cancel the server explicitly, as it will be cancelled when the token is dropped.
pub struct TestServerHandle {
    state: ProverState,
    _token: CancellationToken,
}

impl TestServerHandle {
    pub fn get_client(&self) -> Client {
        Client::new(format!("http://{}", self.state.opts.address))
    }
}
