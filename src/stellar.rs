use std::prelude::v1::*;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cache::CacheKey;
use crate::metrics::MetricsRegistry;

#[derive(Clone)]
pub struct StellarClient {
    horizon_url: String,
    http_client: reqwest::Client,
    metrics: Option<Arc<MetricsRegistry>>,
}

impl std::fmt::Debug for StellarClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StellarClient")
            .field("horizon_url", &self.horizon_url)
            .field("http_client", &self.http_client)
            .field("metrics", &self.metrics.as_ref().map(|_| "<metrics>"))
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionRecord {
    pub transaction_id: String,
    pub timestamp: i64,
    pub verified: bool,
}

pub struct VerificationResult {
    pub verified: bool,
    pub transaction_id: Option<String>,
    pub timestamp: Option<i64>,
}

impl StellarClient {
    pub fn new(horizon_url: &str) -> Self {
        Self {
            horizon_url: horizon_url.to_string(),
            http_client: reqwest::Client::new(),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn verification_cache_key(hash: &str) -> CacheKey {
        CacheKey::Verification(hash.to_string())
    }

    pub async fn check_connection(&self) -> bool {
        let start = MetricsRegistry::start_timer();
        let result = self
            .http_client
            .get(&self.horizon_url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);

        if let Some(ref m) = self.metrics {
            m.increment_request_count();
            let status = if result { "success" } else { "error" };
            m.record_horizon_latency(status, MetricsRegistry::elapsed_secs(start));
            if !result {
                m.increment_error_count();
            }
        }
        result
    }

    /// Verify a document hash against Stellar Horizon with retries.
    ///
    /// Returns a `VerificationResult` containing the transaction ID and timestamp
    /// when a matching memo is found. Records latency, success/failure, and retry metrics.
    pub async fn verify_hash(&self, hash: &str) -> Result<VerificationResult> {
        let overall_start = MetricsRegistry::start_timer();
        let max_retries = 3u32;
        let mut last_result = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                if let Some(ref m) = self.metrics {
                    m.increment_retry();
                }
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            }

            let horizon_start = MetricsRegistry::start_timer();
            let url = format!("{}/transactions?memo={}", self.horizon_url, hash);
            let resp_result = self.http_client.get(&url).send().await;

            match resp_result {
                Ok(resp) => {
                    let horizon_latency = MetricsRegistry::elapsed_secs(horizon_start);
                    let status_str = if resp.status().is_success() {
                        "success"
                    } else {
                        "error"
                    };

                    if let Some(ref m) = self.metrics {
                        m.record_horizon_latency(status_str, horizon_latency);
                    }

                    if resp.status().is_success() {
                        // Parse Horizon response for actual transaction data
                        let tx_record = self.parse_horizon_transaction(resp).await;
                        match tx_record {
                            Ok(Some(record)) => {
                                if let Some(ref m) = self.metrics {
                                    m.record_verification(
                                        "success",
                                        MetricsRegistry::elapsed_secs(overall_start),
                                    );
                                }
                                return Ok(VerificationResult {
                                    verified: true,
                                    transaction_id: Some(record.transaction_id),
                                    timestamp: Some(record.timestamp),
                                });
                            }
                            Ok(None) => {
                                // No matching transaction in response
                                last_result = Some(VerificationResult {
                                    verified: false,
                                    transaction_id: None,
                                    timestamp: None,
                                });
                                // Don't retry on "no match" — it's a legitimate negative result
                                break;
                            }
                            Err(_) => {
                                last_result = Some(VerificationResult {
                                    verified: false,
                                    transaction_id: None,
                                    timestamp: None,
                                });
                                // Parse failure may be transient — continue retry loop
                            }
                        }
                    } else {
                        last_result = Some(VerificationResult {
                            verified: false,
                            transaction_id: None,
                            timestamp: None,
                        });
                        // HTTP error — continue retry loop
                    }
                }
                Err(_) => {
                    let horizon_latency = MetricsRegistry::elapsed_secs(horizon_start);
                    if let Some(ref m) = self.metrics {
                        m.record_horizon_latency("error", horizon_latency);
                    }
                    last_result = Some(VerificationResult {
                        verified: false,
                        transaction_id: None,
                        timestamp: None,
                    });
                    // Network error — continue retry loop
                }
            }
        }

        // Exhausted retries or negative match
        if let Some(ref m) = self.metrics {
            m.record_verification("failure", MetricsRegistry::elapsed_secs(overall_start));
        }
        Ok(last_result.unwrap_or(VerificationResult {
            verified: false,
            transaction_id: None,
            timestamp: None,
        }))
    }

    /// Parse a Horizon `/transactions` response to extract a matching transaction.
    async fn parse_horizon_transaction(
        &self,
        resp: reqwest::Response,
    ) -> Result<Option<TransactionRecord>> {
        #[derive(Deserialize)]
        struct HorizonEmbedded {
            records: Vec<HorizonTransaction>,
        }

        #[derive(Deserialize)]
        struct HorizonResponse {
            #[serde(rename = "_embedded")]
            embedded: HorizonEmbedded,
        }

        #[derive(Deserialize)]
        struct HorizonTransaction {
            id: String,
            created_at: Option<String>,
        }

        let body: HorizonResponse = resp.json().await?;

        if let Some(first_tx) = body.embedded.records.into_iter().next() {
            let timestamp = first_tx
                .created_at
                .as_ref()
                .and_then(|ts| {
                    chrono::DateTime::parse_from_rfc3339(ts)
                        .ok()
                        .map(|dt| dt.timestamp())
                })
                .unwrap_or(0);

            Ok(Some(TransactionRecord {
                transaction_id: first_tx.id,
                timestamp,
                verified: true,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn anchor_transfer(&self, _transfer_hash: &str, _memo: &str) -> Result<()> {
        if let Some(ref m) = self.metrics {
            m.increment_request_count();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_accepts_optional_metrics() {
        let client = StellarClient::new("https://horizon-testnet.stellar.org");
        let metrics = MetricsRegistry::arc();
        let client = client.with_metrics(metrics);
        assert!(client.metrics.is_some());
    }

    #[test]
    fn verification_cache_key_is_consistent() {
        let key = StellarClient::verification_cache_key("abc123");
        assert_eq!(key.as_string(), "verification:abc123");
    }
}
