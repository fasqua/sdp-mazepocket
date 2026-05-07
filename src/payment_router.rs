//! KausaPay Payment Router
//!
//! Probes HTTP 402 responses and orchestrates the x402 payment flow.
//! This is the main entry point for the `POST /pocket/:id/pay` endpoint.

use serde::{Deserialize, Serialize};
use solana_sdk::signature::Keypair;
use tracing::info;

use crate::error::{MazeError, Result};
use crate::x402;
use crate::mpp;

/// Detected payment protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PaymentProtocol {
    X402,
    MPP,
}

impl std::fmt::Display for PaymentProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentProtocol::X402 => write!(f, "x402"),
            PaymentProtocol::MPP => write!(f, "mpp"),
        }
    }
}

/// Unified payment result returned by the router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResult {
    pub success: bool,
    pub response_body: Option<String>,
    pub payment_signature: Option<String>,
    pub amount_paid_usdc: f64,
    pub protocol_used: PaymentProtocol,
    pub token_symbol: String,
    pub error: Option<String>,
}

/// Maximum allowed URL length to prevent abuse
const MAX_URL_LENGTH: usize = 2048;
/// Request timeout for the initial 402 probe
const PROBE_TIMEOUT_SECS: u64 = 30;

/// Main entry point: pay for content at the given URL.
///
/// Flow:
/// 1. Validate the URL (security checks)
/// 2. Make initial GET request to the URL
/// 3. If response is not 402, return error (nothing to pay)
/// 4. Parse x402 challenge from response headers
/// 5. Validate amount against max_amount_usdc
/// 6. Execute payment
/// 7. Return the paid content
pub async fn pay(
    http_client: &reqwest::Client,
    rpc_client: &solana_client::rpc_client::RpcClient,
    pocket_keypair: &Keypair,
    url: &str,
    max_amount_usdc: f64,
    method: &str,
    request_body: Option<&str>,
) -> Result<PaymentResult> {
    // === SECURITY VALIDATIONS ===
    if url.len() > MAX_URL_LENGTH {
        return Err(MazeError::InvalidParameters(
            format!("URL too long. Max {} characters.", MAX_URL_LENGTH)
        ));
    }

    let parsed_url = reqwest::Url::parse(url)
        .map_err(|e| MazeError::InvalidParameters(format!("Invalid URL: {}", e)))?;

    if parsed_url.scheme() != "https" {
        return Err(MazeError::InvalidParameters(
            "KausaPay only supports HTTPS URLs for security.".into()
        ));
    }

    validate_url_not_internal(&parsed_url)?;

    if max_amount_usdc <= 0.0 {
        return Err(MazeError::InvalidParameters(
            "max_amount_usdc must be greater than 0".into()
        ));
    }
    if max_amount_usdc > 1000.0 {
        return Err(MazeError::InvalidParameters(
            "max_amount_usdc cannot exceed 1000 USDC per transaction".into()
        ));
    }

    info!("KausaPay: probing {} (max: {} USDC)", url, max_amount_usdc);

    // === STEP 1: PROBE THE URL ===
    let method_upper = method.to_uppercase();
    let mut probe_req = match method_upper.as_str() {
        "POST" => http_client.post(url),
        "PUT" => http_client.put(url),
        "PATCH" => http_client.patch(url),
        "DELETE" => http_client.delete(url),
        _ => http_client.get(url),
    };
    probe_req = probe_req.timeout(std::time::Duration::from_secs(PROBE_TIMEOUT_SECS));
    if let Some(body) = request_body {
        probe_req = probe_req.header("Content-Type", "application/json").body(body.to_string());
    }
    let probe_response = probe_req
        .send()
        .await
        .map_err(|e| MazeError::RpcError(format!("Failed to reach URL: {}", e)))?;

    let status = probe_response.status().as_u16();

    if status != 402 {
        if status >= 200 && status < 300 {
            let body = probe_response.text().await
                .map_err(|e| MazeError::RpcError(format!("Failed to read response: {}", e)))?;
            return Ok(PaymentResult {
                success: true,
                response_body: Some(body),
                payment_signature: None,
                amount_paid_usdc: 0.0,
                protocol_used: PaymentProtocol::X402,
                token_symbol: "none".into(),
                error: None,
            });
        }
        return Err(MazeError::InvalidParameters(
            format!("URL returned HTTP {} instead of 402. Nothing to pay.", status)
        ));
    }

    // === STEP 2: DETECT PROTOCOL (MPP or x402) ===
    let headers = probe_response.headers().clone();
    let body = probe_response.text().await
        .map_err(|e| MazeError::RpcError(format!("Failed to read 402 response: {}", e)))?;

    // Check for MPP protocol first (WWW-Authenticate: Payment header)
    if let Some(www_auth) = headers.get("www-authenticate")
        .or_else(|| headers.get("WWW-Authenticate"))
    {
        let auth_str = www_auth.to_str()
            .map_err(|_| MazeError::InvalidParameters("Invalid WWW-Authenticate header encoding".into()))?;

        if auth_str.starts_with("Payment ") || auth_str.contains("method=") {
            info!("KausaPay: detected MPP protocol");
            match mpp::parse_mpp_challenge(auth_str) {
                Ok(mpp_challenge) => {
                    info!("KausaPay MPP: {} {} to {} ({})",
                        mpp_challenge.request.amount, mpp_challenge.request.currency,
                        &mpp_challenge.request.recipient[..16.min(mpp_challenge.request.recipient.len())],
                        mpp_challenge.description);

                    let result = mpp::execute_mpp_payment(
                        http_client, rpc_client, pocket_keypair,
                        &mpp_challenge, max_amount_usdc, url, &method_upper, request_body,
                    ).await?;

                    return Ok(PaymentResult {
                        success: result.success,
                        response_body: result.response_body,
                        payment_signature: result.tx_signature,
                        amount_paid_usdc: result.amount_paid,
                        protocol_used: PaymentProtocol::MPP,
                        token_symbol: result.token_symbol,
                        error: result.error,
                    });
                }
                Err(e) => {
                    info!("KausaPay: MPP unsupported ({}), falling back to x402", e);
                }
            }
        }
    }

    // Fallback to x402 protocol (payment-required header)
    let challenge_data = if let Some(header_val) = headers.get("payment-required")
        .or_else(|| headers.get("PAYMENT-REQUIRED"))
        .or_else(|| headers.get("Payment-Required"))
    {
        header_val.to_str()
            .map_err(|_| MazeError::InvalidParameters("Invalid PAYMENT-REQUIRED header encoding".into()))?
            .to_string()
    } else if !body.is_empty() {
        // Some servers put x402 challenge in body instead of header
        body.clone()
    } else {
        return Err(MazeError::InvalidParameters(
            "Server returned 402 but no x402 challenge found in headers or body.".into()
        ));
    };

    let challenge = x402::parse_x402_challenge(&challenge_data)?;

    info!("KausaPay x402: {} {} to {}", challenge.amount_display, challenge.token_symbol,
        &challenge.recipient[..16.min(challenge.recipient.len())]);

    // === STEP 3: EXECUTE PAYMENT ===
    let result = x402::execute_x402_payment(
        http_client,
        rpc_client,
        pocket_keypair,
        &challenge,
        max_amount_usdc,
        url,
        &method_upper,
        request_body,
    ).await?;

    Ok(PaymentResult {
        success: result.success,
        response_body: result.response_body,
        payment_signature: result.tx_signature,
        amount_paid_usdc: result.amount_paid,
        protocol_used: PaymentProtocol::X402,
        token_symbol: result.token_symbol,
        error: result.error,
    })
}

/// SSRF protection: block requests to private/internal IP ranges.
fn validate_url_not_internal(url: &reqwest::Url) -> Result<()> {
    if let Some(host) = url.host_str() {
        let host_lower = host.to_lowercase();

        if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
            return Err(MazeError::InvalidParameters("Cannot pay to localhost URLs.".into()));
        }

        if host_lower == "metadata.google.internal"
            || host_lower == "169.254.169.254"
            || host_lower.ends_with(".internal")
            || host_lower.ends_with(".local")
        {
            return Err(MazeError::InvalidParameters("Cannot pay to internal/metadata URLs.".into()));
        }

        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
                return Err(MazeError::InvalidParameters(
                    format!("Cannot pay to private IP address: {}", ip)
                ));
            }
            if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                return Err(MazeError::InvalidParameters("Cannot pay to link-local address.".into()));
            }
        }

        if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<std::net::Ipv6Addr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                return Err(MazeError::InvalidParameters(
                    format!("Cannot pay to private IPv6 address: {}", ip)
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_localhost() {
        let url = reqwest::Url::parse("https://localhost/api").unwrap();
        assert!(validate_url_not_internal(&url).is_err());
    }

    #[test]
    fn test_block_private_ip() {
        let url = reqwest::Url::parse("https://192.168.1.1/api").unwrap();
        assert!(validate_url_not_internal(&url).is_err());
    }

    #[test]
    fn test_block_metadata() {
        let url = reqwest::Url::parse("https://169.254.169.254/latest/meta-data/").unwrap();
        assert!(validate_url_not_internal(&url).is_err());
    }

    #[test]
    fn test_allow_public_url() {
        let url = reqwest::Url::parse("https://api.example.com/data").unwrap();
        assert!(validate_url_not_internal(&url).is_ok());
    }
}
