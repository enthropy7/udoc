use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HttpSummary {
    pub status: u16,
    pub reason: Option<String>,
    pub version: String,
    pub proto: String,
}

impl HttpSummary {
    pub fn new(status: u16, reason: Option<String>, version: String, proto: String) -> Self {
        Self { status, reason, version, proto }
    }

    pub fn status_line(&self) -> String {
        match &self.reason {
            Some(r) => format!("{} {}", self.status, r),
            None => self.status.to_string(),
        }
    }
}
