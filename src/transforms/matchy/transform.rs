use matchy::extractor::{Extractor, ExtractorBuilder};
use matchy::{Database, QueryResult};
use serde_json::json;
use std::cell::RefCell;
use std::sync::Arc;
use vector_lib::event::Event;

use crate::transforms::{FunctionTransform, OutputBuffer, Transform};

use super::config::{ExtractionConfig, MatchyConfig};

thread_local! {
    static EXTRACTOR: RefCell<Option<Extractor>> = const { RefCell::new(None) };
}

#[derive(Clone)]
pub struct MatchyTransform {
    databases: Vec<(String, Arc<Database>)>,
    extractor_config: Option<Arc<ExtractionConfig>>,
    source_field: String,
    output_field: String,
    match_field: Option<String>,
}

impl MatchyTransform {
    pub fn new(config: MatchyConfig) -> crate::Result<Self> {
        let mut databases = Vec::new();
        for (db_id, db_config) in config.databases {
            let mut opener = Database::from(&db_config.path);

            if db_config.auto_reload.unwrap_or(false) {
                opener = opener.auto_reload();
            }

            let db = opener
                .open()
                .map_err(|e| format!("Failed to open database '{}': {}", db_id, e))?;
            databases.push((db_id, Arc::new(db)));
        }

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
        let log = event.as_mut_log();

        let source_value = match log.get(self.source_field.as_str()) {
            Some(value) => value.to_string_lossy(),
            None => {
                output.push(event);
                return;
            }
        };

        let mut all_matches = Vec::new();

        if let Some(ref config) = self.extractor_config {
            let input_bytes = source_value.as_bytes();

            EXTRACTOR.with(|cell| {
                let mut opt = cell.borrow_mut();
                if opt.is_none() {
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

                for match_item in extractor.extract_from_line(input_bytes) {
                    let item_type = match_item.item.type_name();

                    for (db_id, db) in &self.databases {
                        match db.lookup_extracted(&match_item, input_bytes) {
                            Ok(Some(result)) => {
                                let (json_data, match_type) = match result {
                                    QueryResult::Ip { data, .. } => {
                                        (serde_json::to_value(&data).ok(), "ip")
                                    }
                                    QueryResult::Pattern { data, .. } => {
                                        let first_data = data.into_iter().find_map(|d| d);
                                        (
                                            first_data.and_then(|d| serde_json::to_value(&d).ok()),
                                            "pattern",
                                        )
                                    }
                                    QueryResult::NotFound => (None, "none"),
                                };

                                if let Some(json_data) = json_data {
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
            for (db_id, db) in &self.databases {
                match db.lookup(&source_value) {
                    Ok(Some(result)) => {
                        let (json_data, match_type) = match result {
                            QueryResult::Ip { data, .. } => {
                                (serde_json::to_value(&data).ok(), "ip")
                            }
                            QueryResult::Pattern { data, .. } => {
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

        if !all_matches.is_empty() {
            log.insert(self.output_field.as_str(), json!(all_matches));

            if let Some(ref match_field) = self.match_field {
                log.insert(match_field.as_str(), true);
            }
        } else {
            log.insert(self.output_field.as_str(), json!([]));

            if let Some(ref match_field) = self.match_field {
                log.insert(match_field.as_str(), false);
            }
        }

        output.push(event);
    }
}

pub fn build_transform(config: MatchyConfig) -> crate::Result<Transform> {
    let transform = MatchyTransform::new(config)?;
    Ok(Transform::function(transform))
}

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
