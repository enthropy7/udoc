use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RedirectHop {
    pub status: u16,
    pub from: String,
    pub to: String,
}

impl RedirectHop {
    pub fn new(status: u16, from: String, to: String) -> Self {
        Self { status, from, to }
    }
}
