use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub token_name: String,
    pub command: String,
    pub policy: String,
    pub result: AuditResult,
    pub reason: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub remote_addr: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Allowed,
    Denied,
    InjectionBlocked,
    Error,
}

use tokio::sync::broadcast;

pub struct AuditLogger {
    log_dir: PathBuf,
    broadcast_tx: broadcast::Sender<AuditEntry>,
}

impl AuditLogger {
    pub fn new(log_dir: PathBuf) -> Self {
        fs::create_dir_all(&log_dir).unwrap_or_default();
        let (broadcast_tx, _) = broadcast::channel(1024);
        Self {
            log_dir,
            broadcast_tx,
        }
    }

    /// Subscribe to real-time audit log events
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEntry> {
        self.broadcast_tx.subscribe()
    }

    /// Log an audit entry. Appends as JSON line to a date-stamped log file.
    /// File format: {log_dir}/audit-{YYYY-MM-DD}.jsonl
    pub fn log(&self, entry: &AuditEntry) -> anyhow::Result<()> {
        // Broadcast to live dashboard / websocket subscribers
        let _ = self.broadcast_tx.send(entry.clone());

        let date_str = entry.timestamp.format("%Y-%m-%d").to_string();
        let filename = format!("audit-{}.jsonl", date_str);
        let file_path = self.log_dir.join(filename);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        let mut json = serde_json::to_string(entry)?;
        json.push('\n');

        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Read recent audit entries. Supports filtering by token name and result.
    pub fn read_recent(
        &self,
        limit: usize,
        token_filter: Option<&str>,
        denied_only: bool,
    ) -> anyhow::Result<Vec<AuditEntry>> {
        let mut entries = Vec::new();

        if !self.log_dir.exists() {
            return Ok(entries);
        }

        let mut files: Vec<_> = fs::read_dir(&self.log_dir)?
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name_str = name.to_string_lossy();
                name_str.starts_with("audit-") && name_str.ends_with(".jsonl")
            })
            .collect();

        // Sort files by name in reverse order (newest first)
        files.sort_by_key(|b| std::cmp::Reverse(b.file_name()));

        for file in files {
            if entries.len() >= limit {
                break;
            }

            let file = fs::File::open(file.path())?;
            let reader = BufReader::new(file);
            let mut file_entries = Vec::new();

            for line in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                    file_entries.push(entry);
                }
            }

            // Iterate in reverse since entries inside the file are chronological (oldest to newest)
            for entry in file_entries.into_iter().rev() {
                if entries.len() >= limit {
                    break;
                }

                if matches!(token_filter, Some(token) if entry.token_name != token) {
                    continue;
                }

                if denied_only
                    && entry.result != AuditResult::Denied
                    && entry.result != AuditResult::InjectionBlocked
                {
                    continue;
                }

                entries.push(entry);
            }
        }

        Ok(entries)
    }
}
