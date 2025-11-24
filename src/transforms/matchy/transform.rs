use matchy::extractor::{Extractor, ExtractorBuilder};
use matchy::{Database, QueryResult};
use serde_json::json;
use std::cell::RefCell;
use std::sync::Arc;
use vector_lib::event::Event;

use crate::transforms::{FunctionTransform, OutputBuffer, Transform};

use super::config::{ExtractionConfig, MatchyConfig};

// Thread-local extractor storage - each thread gets its own Extractor instance
// to avoid mutex contention. Extractor is cheap to construct (just config + memchr patterns).
thread_local! {
    static EXTRACTOR: RefCell<Option<Extractor>> = const { RefCell::new(None) };
}

/// The Matchy transform
#[derive(Clone)]
pub struct MatchyTransform {
    /// Loaded databases indexed by database ID
    /// Database is Send + Sync and uses thread-local caching for zero-contention lookups
    databases: Vec<(String, Arc<Database>)>,
    /// Extractor configuration for IoC extraction (if enabled)
    /// We store the config and build a thread-local Extractor on first use per thread
    extractor_config: Option<Arc<ExtractionConfig>>,
    /// Source field to read from events
    source_field: String,
    /// Output field to write results to
    output_field: String,
    /// Optional match flag field
    match_field: Option<String>,
}

impl MatchyTransform {
    pub fn new(config: MatchyConfig) -> crate::Result<Self> {
        // Load all databases
        let mut databases = Vec::new();
        for (db_id, db_config) in config.databases {
            let mut opener = Database::from(&db_config.path);

            // Enable auto-reload if configured
            if db_config.auto_reload.unwrap_or(false) {
                opener = opener.auto_reload();
            }

            let db = opener
                .open()
                .map_err(|e| format!("Failed to open database '{}': {}", db_id, e))?;
            databases.push((db_id, Arc::new(db)));
        }

        // Store extractor config for thread-local initialization
        let extractor_config = config.extract.map(Arc::new);

        Ok(Self {
            databases,
            extractor_config,
            source_field: config.source_field,
            output_field: config.output_field,
            match_field: config.match_field,
        })
    }
}

impl FunctionTransform for MatchyTransform {
    fn transform(&mut self, output: &mut OutputBuffer, mut event: Event) {
        // Only process log events
        let log = event.as_mut_log();

        // Extract the source field value
        let source_value = match log.get(self.source_field.as_str()) {
            Some(value) => value.to_string_lossy(),
            None => {
                // No source field, pass through unchanged
                output.push(event);
                return;
            }
        };

        let mut all_matches = Vec::new();

        // If extraction is enabled, extract IoCs and match them
        if let Some(ref config) = self.extractor_config {
            let input_bytes = source_value.as_bytes();

            // Get or create thread-local extractor
            EXTRACTOR.with(|cell| {
                let mut opt = cell.borrow_mut();
                if opt.is_none() {
                    // First use in this thread - build extractor
                    match build_extractor(config) {
                        Ok(ext) => *opt = Some(ext),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "Failed to build thread-local extractor"
                            );
                            return;
                        }
                    }
                }

                let extractor = opt.as_ref().unwrap();

                // Extract and match
                for match_item in extractor.extract_from_line(input_bytes) {
                    let item_type = match_item.item.type_name();

                    for (db_id, db) in &self.databases {
                        // Use lookup_extracted - handles IP vs string automatically, no conversions needed
                        match db.lookup_extracted(&match_item, input_bytes) {
                            Ok(Some(result)) => {
                                // Extract data based on result type
                                let (json_data, match_type) = match result {
                                    QueryResult::Ip { data, .. } => {
                                        (serde_json::to_value(&data).ok(), "ip")
                                    }
                                    QueryResult::Pattern { data, .. } => {
                                        // Take the first non-None data value
                                        let first_data = data.into_iter().find_map(|d| d);
                                        (
                                            first_data.and_then(|d| serde_json::to_value(&d).ok()),
                                            "pattern",
                                        )
                                    }
                                    QueryResult::NotFound => (None, "none"),
                                };

                                if let Some(json_data) = json_data {
                                    // Only convert to string when needed for output
                                    let matched_text = match_item.as_str(input_bytes);
                                    all_matches.push(json!({
                                        "database_id": db_id,
                                        "matched_text": matched_text,
                                        "extracted_type": item_type,
                                        "match_type": match_type,
                                        "data": json_data,
                                    }));
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                tracing::warn!(
                                    database_id = %db_id,
                                    error = %e,
                                    "Matchy lookup error"
                                );
                            }
                        }
                    }
                }
            });
        } else {
            // No extraction - match the entire field value
            for (db_id, db) in &self.databases {
                match db.lookup(&source_value) {
                    Ok(Some(result)) => {
                        // Extract data based on result type
                        let (json_data, match_type) = match result {
                            QueryResult::Ip { data, .. } => {
                                (serde_json::to_value(&data).ok(), "ip")
                            }
                            QueryResult::Pattern { data, .. } => {
                                // Take the first non-None data value
                                let first_data = data.into_iter().find_map(|d| d);
                                (
                                    first_data.and_then(|d| serde_json::to_value(&d).ok()),
                                    "pattern",
                                )
                            }
                            QueryResult::NotFound => (None, "none"),
                        };

                        if let Some(json_data) = json_data {
                            all_matches.push(json!({
                                "database_id": db_id,
                                "matched_text": source_value.clone(),
                                "match_type": match_type,
                                "data": json_data,
                            }));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(
                            database_id = %db_id,
                            error = %e,
                            "Matchy lookup error"
                        );
                    }
                }
            }
        }

        // Set the output field with matches (if any)
        if !all_matches.is_empty() {
            log.insert(self.output_field.as_str(), json!(all_matches));

            // Set match flag if configured
            if let Some(ref match_field) = self.match_field {
                log.insert(match_field.as_str(), true);
            }
        } else {
            // Set empty array for no matches
            log.insert(self.output_field.as_str(), json!([]));

            // Set match flag to false if configured
            if let Some(ref match_field) = self.match_field {
                log.insert(match_field.as_str(), false);
            }
        }

        output.push(event);
    }
}

/// Build the transform from configuration
pub fn build_transform(config: MatchyConfig) -> crate::Result<Transform> {
    let transform = MatchyTransform::new(config)?;
    Ok(Transform::function(transform))
}

/// Build extractor from configuration
fn build_extractor(config: &ExtractionConfig) -> crate::Result<Extractor> {
    let mut builder = ExtractorBuilder::new();

    builder = builder.extract_domains(config.domains);
    builder = builder.extract_ipv4(config.ipv4);
    builder = builder.extract_ipv6(config.ipv6);
    builder = builder.extract_emails(config.emails);
    builder = builder.extract_hashes(config.hashes);
    builder = builder.extract_bitcoin(config.bitcoin);
    builder = builder.extract_ethereum(config.ethereum);
    builder = builder.extract_monero(config.monero);

    builder
        .build()
        .map_err(|e| format!("Failed to build extractor: {}", e).into())
}
