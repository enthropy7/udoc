use std::process::ExitCode;
use udoc::application::{GenerateReportUseCase, Config};
use udoc::infrastructure::{HickoryDnsResolver, HybridHttpClient, PrettyRenderer, JsonRenderer, RustlsTlsHandshaker, TokioClock, TokioTcpDialer};
use udoc::ports::Renderer;

fn main() -> ExitCode {
    rustls::crypto::ring::default_provider().install_default().ok();

    let args: Vec<String> = std::env::args().collect();

    let (url, json_mode) = match parse_args(&args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{}", msg);
            return ExitCode::from(2);
        }
    };

    let config = Config::from_env().with_json(json_mode);

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error[ERROR]: failed to create runtime: {}", e);
            return ExitCode::from(1);
        }
    };

    rt.block_on(async_main(&url, config))
}

fn parse_args(args: &[String]) -> Result<(String, bool), String> {
    let mut url = None;
    let mut json = false;

    for arg in args.iter().skip(1) {
        if arg == "--json" || arg == "-j" {
            json = true;
        } else if arg == "--help" || arg == "-h" {
            return Err(usage());
        } else if arg.starts_with('-') {
            return Err(format!("unknown option: {}\n\n{}", arg, usage()));
        } else if url.is_none() {
            url = Some(arg.clone());
        } else {
            return Err(format!("unexpected argument: {}\n\n{}", arg, usage()));
        }
    }

    match url {
        Some(u) => Ok((u, json)),
        None => Err(usage()),
    }
}

fn usage() -> String {
    "usage: udoc [--json] <URL>\n\n\
    Prints connection report: DNS/TCP/TLS/TTFB timings + cert summary.\n\n\
    Options:\n  \
      --json, -j    Output as JSON\n\n\
    Environment:\n  \
      UDOC_TIMEOUT     Request timeout (e.g. 5s, 3000ms) [default: 5s]\n  \
      UDOC_MAX_REDIRS  Max redirects [default: 10]\n  \
      UDOC_BODY_LIMIT  Body preview limit in bytes [default: 32768]\n  \
      UDOC_REPEAT      Repeat count for stats [default: 1]".to_string()
}

async fn async_main(url: &str, config: Config) -> ExitCode {
    let repeat = config.repeat.max(1);
    let json_output = config.json_output;

    let dns = match HickoryDnsResolver::new() {
        Ok(d) => d,
        Err(e) => { eprintln!("{}", e); return ExitCode::from(e.class.exit_code() as u8); }
    };

    let tls = match RustlsTlsHandshaker::new() {
        Ok(t) => t,
        Err(e) => { eprintln!("{}", e); return ExitCode::from(e.class.exit_code() as u8); }
    };

    if repeat == 1 {
        let use_case = GenerateReportUseCase::new(dns, TokioTcpDialer::new(), tls, HybridHttpClient::new(), TokioClock::new(), config);
        match use_case.execute(url).await {
            Ok(report) => {
                if json_output {
                    println!("{}", JsonRenderer::new().render(&report));
                } else {
                    print!("{}", PrettyRenderer::new().render(&report));
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{}", e);
                ExitCode::from(e.class.exit_code() as u8)
            }
        }
    } else {
        run_with_stats(url, repeat, json_output, dns, tls, config).await
    }
}

async fn run_with_stats(
    url: &str,
    repeat: usize,
    json_output: bool,
    dns: HickoryDnsResolver,
    tls: RustlsTlsHandshaker,
    config: Config,
) -> ExitCode {
    let _ = (dns, tls);

    let mut total_ms_samples: Vec<f64> = Vec::with_capacity(repeat);
    let mut ttfb_ms_samples: Vec<f64> = Vec::with_capacity(repeat);
    let mut dns_ms_samples: Vec<f64> = Vec::with_capacity(repeat);
    let mut tcp_ms_samples: Vec<f64> = Vec::with_capacity(repeat);
    let mut tls_ms_samples: Vec<f64> = Vec::with_capacity(repeat);
    let mut last_report = None;
    let mut errors = 0;

    for i in 0..repeat {
        let dns_clone = HickoryDnsResolver::new().unwrap_or_else(|_| panic!("dns init"));
        let tls_clone = RustlsTlsHandshaker::new().unwrap_or_else(|_| panic!("tls init"));
        let cfg = Config {
            timeout: config.timeout,
            max_redirects: config.max_redirects,
            body_limit: config.body_limit,
            repeat: 1,
            json_output: false,
        };
        let use_case = GenerateReportUseCase::new(dns_clone, TokioTcpDialer::new(), tls_clone, HybridHttpClient::new(), TokioClock::new(), cfg);

        match use_case.execute(url).await {
            Ok(report) => {
                total_ms_samples.push(report.timings.total_ms);
                ttfb_ms_samples.push(report.timings.ttfb_ms);
                dns_ms_samples.push(report.timings.dns_ms);
                tcp_ms_samples.push(report.timings.tcp_ms);
                if let Some(tls_ms) = report.timings.tls_ms {
                    tls_ms_samples.push(tls_ms);
                }
                last_report = Some(report);
            }
            Err(e) => {
                errors += 1;
                eprintln!("[{}] error: {}", i + 1, e);
            }
        }
    }

    if last_report.is_none() {
        eprintln!("all {} requests failed", repeat);
        return ExitCode::from(1);
    }

    let report = last_report.unwrap();

    if json_output {
        println!("{}", JsonRenderer::new().render(&report));
        let stats = serde_json::json!({
            "stats": {
                "samples": total_ms_samples.len(),
                "errors": errors,
                "total_ms": { "p50": percentile(&mut total_ms_samples, 50), "p95": percentile(&mut total_ms_samples, 95) },
                "ttfb_ms": { "p50": percentile(&mut ttfb_ms_samples, 50), "p95": percentile(&mut ttfb_ms_samples, 95) },
                "dns_ms": { "p50": percentile(&mut dns_ms_samples, 50), "p95": percentile(&mut dns_ms_samples, 95) },
                "tcp_ms": { "p50": percentile(&mut tcp_ms_samples, 50), "p95": percentile(&mut tcp_ms_samples, 95) },
                "tls_ms": if !tls_ms_samples.is_empty() {
                    serde_json::json!({ "p50": percentile(&mut tls_ms_samples, 50), "p95": percentile(&mut tls_ms_samples, 95) })
                } else {
                    serde_json::Value::Null
                }
            }
        });
        println!("{}", serde_json::to_string_pretty(&stats).unwrap_or_default());
    } else {
        print!("{}", PrettyRenderer::new().render(&report));
        println!("\nSTATS ({} samples, {} errors)", total_ms_samples.len(), errors);
        println!("  total:  p50={:.1}ms  p95={:.1}ms", percentile(&mut total_ms_samples, 50), percentile(&mut total_ms_samples, 95));
        println!("  ttfb:   p50={:.1}ms  p95={:.1}ms", percentile(&mut ttfb_ms_samples, 50), percentile(&mut ttfb_ms_samples, 95));
        println!("  dns:    p50={:.1}ms  p95={:.1}ms", percentile(&mut dns_ms_samples, 50), percentile(&mut dns_ms_samples, 95));
        println!("  tcp:    p50={:.1}ms  p95={:.1}ms", percentile(&mut tcp_ms_samples, 50), percentile(&mut tcp_ms_samples, 95));
        if !tls_ms_samples.is_empty() {
            println!("  tls:    p50={:.1}ms  p95={:.1}ms", percentile(&mut tls_ms_samples, 50), percentile(&mut tls_ms_samples, 95));
        }
    }

    ExitCode::SUCCESS
}

fn percentile(samples: &mut Vec<f64>, p: usize) -> f64 {
    if samples.is_empty() { return 0.0; }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (samples.len() * p / 100).min(samples.len() - 1);
    samples[idx]
}
