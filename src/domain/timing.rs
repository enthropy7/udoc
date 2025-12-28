use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct HopTiming {
    pub dns_ms: f64,
    pub tcp_ms: f64,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: f64,
}

impl HopTiming {
    pub fn total(&self) -> f64 {
        self.dns_ms + self.tcp_ms + self.tls_ms.unwrap_or(0.0) + self.ttfb_ms
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TimingBreakdown {
    pub dns_ms: f64,
    pub tcp_ms: f64,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: f64,
    pub total_ms: f64,
    pub hops: Vec<HopTiming>,
}

impl TimingBreakdown {
    pub fn new(dns_ms: f64, tcp_ms: f64, tls_ms: Option<f64>, ttfb_ms: f64, total_ms: f64) -> Self {
        Self { dns_ms, tcp_ms, tls_ms, ttfb_ms, total_ms, hops: Vec::new() }
    }

    pub fn with_hops(mut self, hops: Vec<HopTiming>) -> Self {
        self.hops = hops;
        self
    }
}
