use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::TokioExecutor;
use crate::domain::{HttpSummary, UdocError};
use crate::ports::{HttpClient, HttpResponse, ResponseHeaders, BoxedIoStream};

const HEADER_LIMIT: usize = 32 * 1024;

pub struct HybridHttpClient;

impl HybridHttpClient {
    pub fn new() -> Self { Self }
}

impl HttpClient for HybridHttpClient {
    async fn request_h1(&self, mut stream: BoxedIoStream, method: &str, host: &str, port: u16, path: &str, is_https: bool, body_limit: usize) -> Result<HttpResponse, UdocError> {
        let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };

        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: udoc/0.1\r\nAccept: */*\r\n\r\n",
            method, path, host_header
        );

        let start = Instant::now();
        stream.write_all(request.as_bytes()).await.map_err(|e| UdocError::http(format!("failed to send request: {}", e)))?;

        let mut buffer = vec![0u8; HEADER_LIMIT + body_limit];
        let mut total_read = 0;
        let mut first_byte_time: Option<f64> = None;

        loop {
            let n = stream.read(&mut buffer[total_read..]).await.map_err(|e| UdocError::http(format!("failed to read response: {}", e)))?;
            if n == 0 { break; }
            if first_byte_time.is_none() { first_byte_time = Some(start.elapsed().as_secs_f64() * 1000.0); }
            total_read += n;

            if let Some(pos) = find_header_end(&buffer[..total_read]) {
                let body_so_far = total_read.saturating_sub(pos + 4);
                if body_so_far >= body_limit { break; }
            }
            if total_read >= buffer.len() { break; }
        }
        buffer.truncate(total_read);

        let (summary, headers, body_start) = parse_response_with_1xx_skip(&buffer, if is_https { "HTTPS" } else { "HTTP" })?;

        let body_preview = if body_start < buffer.len() {
            let raw_body = &buffer[body_start..];
            if headers.transfer_encoding.as_ref().map(|t| t.contains("chunked")).unwrap_or(false) {
                decode_chunked_preview(raw_body, body_limit)
            } else {
                raw_body[..raw_body.len().min(body_limit)].to_vec()
            }
        } else {
            Vec::new()
        };

        Ok(HttpResponse { summary, headers, ttfb_ms: first_byte_time.unwrap_or(0.0), body_preview })
    }

    async fn request_h2(&self, stream: BoxedIoStream, method: &str, host: &str, port: u16, path: &str, body_limit: usize) -> Result<HttpResponse, UdocError> {
        let host_header = if port == 443 { host.to_string() } else { format!("{}:{}", host, port) };
        let authority = host_header.clone();
        let uri = format!("https://{}{}", authority, path);

        let start = Instant::now();

        let io = TokioIo(stream);
        let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await
            .map_err(|e| UdocError::http(format!("h2 handshake failed: {}", e)))?;

        tokio::spawn(async move { let _ = conn.await; });

        let req = hyper::Request::builder()
            .method(method)
            .uri(&uri)
            .header("host", &host_header)
            .header("user-agent", "udoc/0.1")
            .header("accept", "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(|e| UdocError::http(format!("failed to build request: {}", e)))?;

        let res = sender.send_request(req).await
            .map_err(|e| UdocError::http(format!("h2 request failed: {}", e)))?;

        let ttfb_ms = start.elapsed().as_secs_f64() * 1000.0;

        let status = res.status().as_u16();
        let reason = res.status().canonical_reason().map(|s| s.to_string());

        let mut headers = ResponseHeaders::default();
        for (key, value) in res.headers() {
            let key_str = key.as_str();
            let val_str = value.to_str().unwrap_or("");
            match key_str {
                "location" => headers.location = Some(val_str.to_string()),
                "server" => headers.server = Some(val_str.to_string()),
                "content-type" => headers.content_type = Some(val_str.to_string()),
                "content-length" => headers.content_length = val_str.parse().ok(),
                "transfer-encoding" => headers.transfer_encoding = Some(val_str.to_string()),
                _ => {}
            }
        }

        let mut body_preview = Vec::with_capacity(body_limit.min(8192));
        let mut body = res.into_body();
        while body_preview.len() < body_limit {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(chunk) = frame.data_ref() {
                        let remaining = body_limit - body_preview.len();
                        let to_copy = chunk.len().min(remaining);
                        body_preview.extend_from_slice(&chunk[..to_copy]);
                    }
                }
                Some(Err(e)) => return Err(UdocError::http(format!("failed to read h2 body: {}", e))),
                None => break,
            }
        }
        drop(body);

        Ok(HttpResponse {
            summary: HttpSummary::new(status, reason, "h2".to_string(), "HTTPS".to_string()),
            headers,
            ttfb_ms,
            body_preview,
        })
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i+4] == b"\r\n\r\n" { return Some(i); }
    }
    None
}

fn parse_response_with_1xx_skip(data: &[u8], proto: &str) -> Result<(HttpSummary, ResponseHeaders, usize), UdocError> {
    let mut offset = 0;
    loop {
        let remaining = &data[offset..];
        let headers_end = find_header_end(remaining).ok_or_else(|| UdocError::http("incomplete HTTP response"))?;
        let header_bytes = &remaining[..headers_end];
        let (summary, headers) = parse_headers(header_bytes, proto)?;

        if summary.status >= 100 && summary.status < 200 {
            offset += headers_end + 4;
            continue;
        }

        return Ok((summary, headers, offset + headers_end + 4));
    }
}

fn parse_headers(header_bytes: &[u8], proto: &str) -> Result<(HttpSummary, ResponseHeaders), UdocError> {
    let mut lines = header_bytes.split(|&b| b == b'\n');
    let status_line = lines.next().ok_or_else(|| UdocError::http("missing status line"))?;
    let status_line = std::str::from_utf8(status_line).map_err(|_| UdocError::http("invalid status line encoding"))?;
    let status_line = status_line.trim_end_matches('\r');

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(UdocError::http(format!("invalid status line: {}", status_line)));
    }

    let version = if parts[0].contains("1.1") { "http/1.1" }
        else if parts[0].contains("1.0") { "http/1.0" }
        else if parts[0].contains("2") { "h2" }
        else { "http/1.1" }.to_string();

    let status: u16 = parts[1].parse().map_err(|_| UdocError::http(format!("invalid status code: {}", parts[1])))?;
    let reason = parts.get(2).map(|s| s.to_string());

    let mut headers = ResponseHeaders::default();
    for line in lines {
        let line = std::str::from_utf8(line).unwrap_or("");
        let line = line.trim_end_matches('\r');
        if line.is_empty() { continue; }
        if let Some((key, value)) = line.split_once(':') {
            let key_lower = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match key_lower.as_str() {
                "location" => headers.location = Some(value.to_string()),
                "server" => headers.server = Some(value.to_string()),
                "content-type" => headers.content_type = Some(value.to_string()),
                "content-length" => headers.content_length = value.parse().ok(),
                "transfer-encoding" => headers.transfer_encoding = Some(value.to_ascii_lowercase()),
                _ => {}
            }
        }
    }

    Ok((HttpSummary::new(status, reason, version, proto.to_string()), headers))
}

fn decode_chunked_preview(data: &[u8], limit: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() && result.len() < limit {
        let line_end = data[pos..].iter().position(|&b| b == b'\n').map(|p| pos + p);
        let line_end = match line_end { Some(e) => e, None => break };

        let size_line = &data[pos..line_end];
        let size_str = std::str::from_utf8(size_line).unwrap_or("").trim_end_matches('\r');
        let size_str = size_str.split(';').next().unwrap_or("");
        let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);

        if chunk_size == 0 { break; }

        pos = line_end + 1;
        let chunk_end = (pos + chunk_size).min(data.len());
        let to_copy = (limit - result.len()).min(chunk_end - pos);
        result.extend_from_slice(&data[pos..pos + to_copy]);

        pos = chunk_end + 2;
    }

    result
}

struct TokioIo(BoxedIoStream);

impl hyper::rt::Read for TokioIo {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut tbuf = tokio::io::ReadBuf::uninit(unsafe { buf.as_mut() });
        match std::pin::Pin::new(&mut self.0).poll_read(cx, &mut tbuf) {
            std::task::Poll::Ready(Ok(())) => {
                let n = tbuf.filled().len();
                unsafe { buf.advance(n); }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl hyper::rt::Write for TokioIo {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
