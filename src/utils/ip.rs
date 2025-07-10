use axum::http::{HeaderMap, StatusCode};
use std::net::{IpAddr, SocketAddr};

use crate::security::SecurityValidator;

/// Extract real client IP from headers or connection info
/// 
/// This function checks various headers commonly used by reverse proxies
/// to determine the real client IP address:
/// 
/// 1. X-Forwarded-For (standard reverse proxy header)
/// 2. X-Real-IP (nginx style header)
/// 3. CF-Connecting-IP (CloudFlare header)
/// 4. Direct connection IP (fallback)
/// 
/// # Arguments
/// * `headers` - HTTP headers from the request
/// * `connect_info` - Direct TCP connection information
/// 
/// # Returns
/// The real client IP address
pub fn extract_real_ip(headers: &HeaderMap, connect_info: &SocketAddr) -> IpAddr {
    // Check X-Forwarded-For header (standard reverse proxy header)
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // Take the first one (original client)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    
    // Check X-Real-IP header (nginx style)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }
    
    // Check CF-Connecting-IP header (CloudFlare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(cf_ip_str) = cf_ip.to_str() {
            if let Ok(ip) = cf_ip_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }
    
    // Fallback to direct connection IP
    connect_info.ip()
}

/// Validate IP address access with real IP extraction
/// 
/// This function extracts the real client IP and validates it against
/// the security policy if one is configured.
/// 
/// # Arguments
/// * `security` - Optional security validator containing IP allowlists
/// * `headers` - HTTP headers from the request
/// * `connect_info` - Direct TCP connection information
/// 
/// # Returns
/// * `Ok(IpAddr)` - The validated real client IP
/// * `Err(StatusCode)` - HTTP 403 Forbidden if IP is not allowed
pub fn validate_ip_access(
    security: &Option<SecurityValidator>, 
    headers: &HeaderMap, 
    connect_info: &SocketAddr
) -> Result<IpAddr, StatusCode> {
    let real_ip = extract_real_ip(headers, connect_info);
    
    if let Some(security) = security {
        if let Err(_) = security.validate_ip(&real_ip) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(real_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::SocketAddr;

    #[test]
    fn test_extract_real_ip_direct_connection() {
        let headers = HeaderMap::new();
        let connect_info: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let ip = extract_real_ip(&headers, &connect_info);
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_extract_real_ip_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178".parse().unwrap());
        let connect_info: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let ip = extract_real_ip(&headers, &connect_info);
        assert_eq!(ip.to_string(), "203.0.113.195");
    }

    #[test]
    fn test_extract_real_ip_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.195".parse().unwrap());
        let connect_info: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let ip = extract_real_ip(&headers, &connect_info);
        assert_eq!(ip.to_string(), "203.0.113.195");
    }

    #[test]
    fn test_extract_real_ip_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.195".parse().unwrap());
        let connect_info: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let ip = extract_real_ip(&headers, &connect_info);
        assert_eq!(ip.to_string(), "203.0.113.195");
    }

    #[test]
    fn test_extract_real_ip_priority() {
        let mut headers = HeaderMap::new();
        // X-Forwarded-For should have priority
        headers.insert("x-forwarded-for", "203.0.113.195".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.178".parse().unwrap());
        headers.insert("cf-connecting-ip", "198.51.100.179".parse().unwrap());
        let connect_info: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let ip = extract_real_ip(&headers, &connect_info);
        assert_eq!(ip.to_string(), "203.0.113.195");
    }
} 