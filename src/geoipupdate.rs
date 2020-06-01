use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use log::{error, warn};
use maxminddb::Reader;
use md5;
use prometheus::{IntCounter, IntGauge};
use reqwest::{Client, StatusCode};
use std::io::Read;
use std::time::Duration;
use tokio::time;

use std::sync::{Arc, RwLock};

pub type MaxMindReader = Option<Reader<Vec<u8>>>;

pub struct GeoIPUpdaterMetrics {
    last_modified: IntGauge,
    last_checked: IntGauge,
    errors: IntCounter,
}

impl GeoIPUpdaterMetrics {
    pub fn new(
        last_modified: IntGauge,
        last_checked: IntGauge,
        errors: IntCounter,
    ) -> GeoIPUpdaterMetrics {
        GeoIPUpdaterMetrics {
            last_modified,
            last_checked,
            errors,
        }
    }
}

pub struct GeoIPUpdater {
    md5: String,
    db: Arc<RwLock<MaxMindReader>>,
    update_interval: Duration,
    account_id: String,
    license_key: String,
    edition_id: String,
    metrics: GeoIPUpdaterMetrics,
}

impl GeoIPUpdater {
    pub fn new(
        update_minutes: u64,
        db: Arc<RwLock<MaxMindReader>>,
        account_id: String,
        license_key: String,
        edition_id: String,
        metrics: GeoIPUpdaterMetrics,
    ) -> GeoIPUpdater {
        GeoIPUpdater {
            md5: "00000000000000000000000000000000".to_owned(),
            update_interval: Duration::from_secs(update_minutes * 60),
            db,
            account_id,
            license_key,
            edition_id,
            metrics,
        }
    }

    async fn renew(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        warn!("Fetching GeoIP Database");
        let client = Client::new();
        let resp = client
            .get(&format!(
                "https://updates.maxmind.com/geoip/databases/{}/update?db_md5={}",
                &self.edition_id, self.md5
            ))
            .basic_auth(&self.account_id, Some(&self.license_key))
            .send()
            .await?;

        let status = resp.status();
        match status {
            StatusCode::NOT_MODIFIED => {
                warn!("GeoIP Database not modified");
                self.metrics.last_checked.set(Utc::now().timestamp());
                Ok(())
            }
            StatusCode::OK => {
                let md5 = resp
                    .headers()
                    .get("X-Database-MD5")
                    .ok_or("X-Database-MD5 does not exist")?
                    .to_str()?
                    .to_owned();
                let last_modified = resp
                    .headers()
                    .get(reqwest::header::LAST_MODIFIED)
                    .ok_or("Last Modified header not sent")?
                    .to_str()?
                    .to_owned();

                let reader = self.parse_response(resp, &md5).await?;
                let mut old_reader = self.db.as_ref().write().unwrap();
                *old_reader = Some(reader);
                self.md5 = md5.to_string();

                let last_modified = DateTime::parse_from_rfc2822(&last_modified)?.timestamp();
                self.metrics.last_modified.set(last_modified);
                warn!("Updated GeoIP Database");
                self.metrics.last_checked.set(Utc::now().timestamp());
                Ok(())
            }
            _ => {
                self.metrics.errors.inc();
                Err(format!("Got status code {}", status).into())
            }
        }
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            let mut interval_day = time::interval(self.update_interval);
            loop {
                let _now = interval_day.tick().await;
                if let Err(e) = &self.renew().await {
                    error!("Error fetching database: {}", e)
                }
            }
        });
    }

    async fn parse_response(
        &self,
        resp: reqwest::Response,
        header_md5: &str,
    ) -> Result<Reader<Vec<u8>>, Box<dyn std::error::Error>> {
        let gzipped_body = resp.bytes().await?;
        let mut decoder = GzDecoder::new(gzipped_body.as_ref());
        let mut decompressed_body = Vec::new();
        decoder.read_to_end(&mut decompressed_body)?;

        let file_md5 = format!("{:x}", md5::compute(&decompressed_body));
        if file_md5 != *header_md5 {
            return Err(format!(
                "Checksums did not match.  File: {}, Header: {}",
                file_md5, header_md5
            )
            .into());
        }

        Ok(Reader::from_source(decompressed_body)?)
    }
}
