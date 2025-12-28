use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TlsSummary {
    pub version: String,
    pub alpn: Option<String>,
    pub cipher: String,
    pub chain_len: usize,
    pub verified: bool,
}

impl TlsSummary {
    pub fn new(version: String, alpn: Option<String>, cipher: String, chain_len: usize, verified: bool) -> Self {
        Self { version, alpn, cipher, chain_len, verified }
    }

    pub fn is_h2(&self) -> bool {
        self.alpn.as_ref().map(|a| a == "h2").unwrap_or(false)
    }
}
