use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Event {
    #[serde(rename = "validated")]
    Validated,
    #[serde(rename = "accepted")]
    Accepted,
}
