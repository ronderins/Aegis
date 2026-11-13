//! Official ZK-Auth Rust Asynchronous Client SDK
//!
//! Provides high-level asynchronous bindings for creating identity sessions,
//! requesting zero-knowledge proofs, polling validation receipts, and checking nullifier status.

use crate::models::{ProofReceipt, SessionResponse, VerifyProofRequest, VerifyProofResponse};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct ZkAuthClient {
    pub base_url: String,
    pub api_key: Option<String>,
}

impl ZkAuthClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    fn parse_host_port(&self) -> Result<(String, String), String> {
        let stripped = self
            .base_url
            .strip_prefix("http://")
            .or_else(|| self.base_url.strip_prefix("https://"))
            .unwrap_or(&self.base_url);
        let (host_port, base_path) = match stripped.split_once('/') {
            Some((hp, p)) => (hp.to_string(), format!("/{}", p.trim_end_matches('/'))),
            None => (stripped.to_string(), String::new()),
        };
        if host_port.is_empty() {
            return Err("Invalid base_url".to_string());
        }
        Ok((host_port, base_path))
    }

    async fn request_json<B: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
    ) -> Result<R, String> {
        let (host_port, base_path) = self.parse_host_port()?;
        let full_path = format!("{}{}", base_path, path);
        let payload = match body {
            Some(b) => serde_json::to_string(b).map_err(|e| format!("Serialize error: {}", e))?,
            None => String::new(),
        };

        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n",
            method, full_path, host_port
        );
        if let Some(key) = &self.api_key {
            req.push_str(&format!("X-API-Key: {}\r\n", key));
        }
        if !payload.is_empty() {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                payload.len()
            ));
        }
        req.push_str("\r\n");
        req.push_str(&payload);

        let mut stream = TcpStream::connect(&host_port)
            .await
            .map_err(|e| format!("HTTP connection failed: {}", e))?;
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("HTTP write failed: {}", e))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| format!("HTTP read failed: {}", e))?;

        let text = String::from_utf8_lossy(&raw);
        let (_, json_body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| "Malformed HTTP response".to_string())?;
        serde_json::from_str::<R>(json_body.trim())
            .map_err(|e| format!("Failed to parse JSON response: {}", e))
    }

    /// Initializes a one-time cryptographic blind verification QR session
    pub async fn create_session(&self) -> Result<SessionResponse, String> {
        self.request_json::<(), SessionResponse>("GET", "/api/v1/session", None)
            .await
    }

    /// Submits a zero-knowledge proof request
    pub async fn verify_identity(
        &self,
        request: &VerifyProofRequest,
    ) -> Result<VerifyProofResponse, String> {
        self.request_json("POST", "/api/v1/verify", Some(request))
            .await
    }

    /// Retrieves a tamper-evident audit receipt by proof ID
    pub async fn get_receipt(&self, proof_id: &str) -> Result<ProofReceipt, String> {
        let path = format!("/api/v1/proofs/{}", proof_id);
        self.request_json::<(), ProofReceipt>("GET", &path, None)
            .await
    }
}
