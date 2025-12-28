use super::{CertSummary, HttpSummary, RedirectHop, ResolvedTarget, TimingBreakdown, TlsSummary};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub input_url: String,
    pub final_url: String,
    pub host: String,
    pub resolved: ResolvedTarget,
    pub redirects: Vec<RedirectHop>,
    pub timings: TimingBreakdown,
    pub http: HttpSummary,
    pub tls: Option<TlsSummary>,
    pub cert: Option<CertSummary>,
    pub was_downgrade: bool,
}

impl Report {
    pub fn bottleneck(&self) -> &'static str {
        let dns = self.timings.dns_ms;
        let tcp = self.timings.tcp_ms;
        let tls = self.timings.tls_ms.unwrap_or(0.0);
        let ttfb = self.timings.ttfb_ms;

        let max = dns.max(tcp).max(tls).max(ttfb);
        if max < 10.0 { return "none (fast)"; }

        if ttfb >= dns && ttfb >= tcp && ttfb >= tls { return "ttfb (server)"; }
        if dns >= tcp && dns >= tls { return "dns"; }
        if tls >= tcp { return "tls"; }
        "tcp"
    }
}
