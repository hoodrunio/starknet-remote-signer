use axum::http::HeaderValue;

/// Middleware to add security headers to all responses
pub async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;

    // Add security headers using static values to avoid parse failures
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));

    // Remove server information
    headers.remove("server");

    response
}
