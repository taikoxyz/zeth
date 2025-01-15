use crate::{RequestEntity, RequestKey};
use raiko_reqpool::impl_display_using_json_pretty;
use serde::{Deserialize, Serialize};

/// The action message sent from **external** to the actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Prove {
        request_key: RequestKey,
        request_entity: RequestEntity,
    },
    Cancel {
        request_key: RequestKey,
    },
}

impl Action {
    pub fn request_key(&self) -> &RequestKey {
        match self {
            Action::Prove { request_key, .. } => request_key,
            Action::Cancel { request_key, .. } => request_key,
        }
    }
}

impl_display_using_json_pretty!(Action);
