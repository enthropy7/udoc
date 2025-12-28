use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub subject_cn: Option<String>,
    pub issuer: String,
    pub san_short: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub sha256_fp: String,
}

impl CertSummary {
    pub fn short_fingerprint(&self) -> String {
        let parts: Vec<&str> = self.sha256_fp.split(':').collect();
        if parts.len() <= 6 {
            return self.sha256_fp.clone();
        }
        format!("{}:{}:...:{}",parts[0], parts[1], parts[parts.len() - 1])
    }

    pub fn validity_range(&self) -> String {
        let start = self.not_before.split('T').next().unwrap_or(&self.not_before);
        let end = self.not_after.split('T').next().unwrap_or(&self.not_after);
        format!("{} → {}  (days_left: {})", start, end, self.days_left)
    }
}
