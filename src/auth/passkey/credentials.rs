use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Credentials {
    id: String,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl Credentials {
    pub(crate) fn from_id(id: String) -> Self {
        Self {
            id,
            typ: "public-key",
        }
    }
}
