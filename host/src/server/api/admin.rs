use axum::{extract::State, routing::post, Router};

use crate::{interfaces::HostResult, ProverState};

pub fn create_router() -> Router<ProverState> {
    Router::new()
        .route("/admin/pause", post(pause))
        .route("/admin/unpause", post(unpause))
}

async fn pause(State(state): State<ProverState>) -> HostResult<&'static str> {
    state.set_pause(true).await?;
    Ok("System paused successfully")
}

async fn unpause(State(state): State<ProverState>) -> HostResult<&'static str> {
    state.set_pause(false).await?;
    Ok("System unpaused successfully")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use clap::Parser;
    use std::path::PathBuf;
    use tower::ServiceExt;

    #[serial_test::serial]
    #[test_log::test(tokio::test)]
    async fn test_pause() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();
        let app = Router::new()
            .route("/admin/pause", post(pause))
            .with_state(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/admin/pause")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.is_paused());
    }

    #[serial_test::serial]
    #[test_log::test(tokio::test)]
    async fn test_pause_when_already_paused() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();

        state.set_pause(true).await.unwrap();

        let app = Router::new()
            .route("/admin/pause", post(pause))
            .with_state(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/admin/pause")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.is_paused());
    }

    #[serial_test::serial]
    #[test_log::test(tokio::test)]
    async fn test_unpause() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();

        // Set initial paused state
        state.set_pause(true).await.unwrap();
        assert!(state.is_paused());

        let app = Router::new()
            .route("/admin/unpause", post(unpause))
            .with_state(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/admin/unpause")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!state.is_paused());
    }
}
