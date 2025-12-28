use crate::domain::Report;
use crate::ports::Renderer;
use serde::Serialize;

pub struct PrettyRenderer;

impl PrettyRenderer {
    pub fn new() -> Self { Self }
}

impl Renderer for PrettyRenderer {
    fn render(&self, report: &Report) -> String {
        let mut out = String::new();

        let tls_ver = report.tls.as_ref().map(|t| t.version.as_str()).unwrap_or("-");
        let proto_ver = &report.http.version;
        out.push_str(&format!(
            "{} {}  {}  ip={}  total={:.1}ms  ttfb={:.1}ms  tls={}  bottleneck={}\n",
            report.http.status,
            report.http.reason.as_deref().unwrap_or(""),
            proto_ver,
            report.resolved.ip,
            report.timings.total_ms,
            report.timings.ttfb_ms,
            tls_ver,
            report.bottleneck()
        ));

        if report.was_downgrade {
            out.push_str("⚠ WARNING: HTTPS→HTTP downgrade detected!\n");
        }

        if let Some(ref cert) = report.cert {
            if cert.days_left < 14 {
                out.push_str(&format!("⚠ CERT EXPIRING in {} days!\n", cert.days_left));
            }
        }

        out.push('\n');
        out.push_str("URL\n");
        out.push_str(&format!("  input:  {}\n", report.input_url));
        out.push_str(&format!("  final:  {}\n", report.final_url));
        out.push_str(&format!("  host:   {}\n", report.host));
        out.push_str(&format!("  ip:     {}   ({})\n", report.resolved.as_socket_str(), report.resolved.family));
        if report.resolved.all_ips.len() > 1 {
            out.push_str(&format!("  ips:    {}\n", report.resolved.ips_short()));
        }

        if !report.redirects.is_empty() {
            out.push('\n');
            out.push_str(&format!("REDIRECTS ({})\n", report.redirects.len()));
            for (i, hop) in report.redirects.iter().enumerate() {
                out.push_str(&format!("  [{}] {} → {}\n", hop.status, shorten_url(&hop.from, 40), shorten_url(&hop.to, 40)));
                if i < report.timings.hops.len() {
                    let ht = &report.timings.hops[i];
                    out.push_str(&format!("      dns={:.1}ms tcp={:.1}ms", ht.dns_ms, ht.tcp_ms));
                    if let Some(tls) = ht.tls_ms { out.push_str(&format!(" tls={:.1}ms", tls)); }
                    out.push_str(&format!(" ttfb={:.1}ms\n", ht.ttfb_ms));
                }
            }
        }

        out.push('\n');
        out.push_str("HTTP\n");
        out.push_str(&format!("  status: {}\n", report.http.status_line()));
        out.push_str(&format!("  proto:  {}\n", report.http.proto));
        out.push_str(&format!("  ver:    {}\n", report.http.version));

        out.push('\n');
        out.push_str("TIMINGS\n");
        out.push_str(&format!("  dns:    {:>8.1} ms\n", report.timings.dns_ms));
        out.push_str(&format!("  tcp:    {:>8.1} ms\n", report.timings.tcp_ms));
        if let Some(tls_ms) = report.timings.tls_ms {
            out.push_str(&format!("  tls:    {:>8.1} ms\n", tls_ms));
        }
        out.push_str(&format!("  ttfb:   {:>8.1} ms\n", report.timings.ttfb_ms));
        out.push_str(&format!("  total:  {:>8.1} ms\n", report.timings.total_ms));

        if let Some(ref tls) = report.tls {
            out.push('\n');
            out.push_str("TLS\n");
            out.push_str(&format!("  version: {}\n", tls.version));
            if let Some(ref alpn) = tls.alpn { out.push_str(&format!("  alpn:    {}\n", alpn)); }
            out.push_str(&format!("  cipher:  {}\n", tls.cipher));
            out.push_str(&format!("  chain:   {} certs\n", tls.chain_len));
            out.push_str(&format!("  verify:  {}\n", if tls.verified { "ok" } else { "FAILED" }));
        }

        if let Some(ref cert) = report.cert {
            out.push('\n');
            out.push_str("CERT\n");
            if let Some(ref cn) = cert.subject_cn { out.push_str(&format!("  subject: CN={}\n", cn)); }
            out.push_str(&format!("  issuer:  {}\n", cert.issuer));
            if !cert.san_short.is_empty() { out.push_str(&format!("  san:     {}\n", cert.san_short)); }
            out.push_str(&format!("  valid:   {}\n", cert.validity_range()));
            out.push_str(&format!("  sha256:  {}\n", cert.short_fingerprint()));
        }

        out
    }
}

fn shorten_url(url: &str, max: usize) -> String {
    if url.len() <= max { url.to_string() } else { format!("{}...", &url[..max.saturating_sub(3)]) }
}

pub struct JsonRenderer;

impl JsonRenderer {
    pub fn new() -> Self { Self }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(flatten)]
    report: &'a Report,
    bottleneck: &'static str,
}

impl Renderer for JsonRenderer {
    fn render(&self, report: &Report) -> String {
        let json_report = JsonReport {
            report,
            bottleneck: report.bottleneck(),
        };
        serde_json::to_string_pretty(&json_report).unwrap_or_else(|_| "{}".to_string())
    }
}
