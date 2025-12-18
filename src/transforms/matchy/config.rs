use std::collections::HashMap;
use vector_lib::{
    config::{LogNamespace, clone_input_definitions},
    configurable::configurable_component,
};

use crate::{
    config::{
        DataType, GenerateConfig, Input, OutputId, TransformConfig, TransformContext,
        TransformOutput,
    },
    schema,
    transforms::Transform,
};

/// Configuration for a single matchy database
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Path to the matchy database file (.mxy or .mmdb)
    pub path: String,

    /// Enable automatic reload when the database file changes
    ///
    /// When enabled, the database will watch its source file and automatically
    /// reload when changes are detected. All queries transparently use the latest
    /// version with zero downtime. Uses lock-free atomic swapping for minimal overhead.
    #[serde(default)]
    pub auto_reload: Option<bool>,

    /// Enable automatic updates from the database's embedded update URL
    ///
    /// When enabled, the database will periodically check its embedded URL for updates
    /// using HTTP conditional GET (ETag). Updates are downloaded to a cache directory,
    /// leaving the original file untouched. The database must have an update URL embedded
    /// in its metadata (set during build with `matchy build --update-url`).
    #[serde(default)]
    pub auto_update: Option<bool>,

    /// How often to check for remote updates (in seconds)
    ///
    /// Only used when `auto_update` is enabled. Default: 3600 (1 hour).
    #[serde(default)]
    pub update_interval_secs: Option<u64>,

    /// Directory to cache downloaded database updates
    ///
    /// Only used when `auto_update` is enabled. Default: system cache directory
    /// (~/.cache/matchy/ on Unix, %LOCALAPPDATA%\matchy\ on Windows).
    #[serde(default)]
    pub cache_dir: Option<String>,

    /// LRU cache capacity for query results
    ///
    /// Set to 0 to disable caching. Default: 10000 entries.
    #[serde(default)]
    pub cache_capacity: Option<usize>,
}

/// Configuration for extraction settings
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExtractionConfig {
    /// Extract domain names from events
    #[serde(default = "default_true")]
    pub domains: bool,

    /// Extract IPv4 addresses from events
    #[serde(default = "default_true")]
    pub ipv4: bool,

    /// Extract IPv6 addresses from events
    #[serde(default = "default_true")]
    pub ipv6: bool,

    /// Extract email addresses from events
    #[serde(default = "default_false")]
    pub emails: bool,

    /// Extract file hashes (MD5, SHA1, SHA256) from events
    #[serde(default = "default_true")]
    pub hashes: bool,

    /// Extract Bitcoin addresses from events
    #[serde(default = "default_false")]
    pub bitcoin: bool,

    /// Extract Ethereum addresses from events
    #[serde(default = "default_false")]
    pub ethereum: bool,

    /// Extract Monero addresses from events
    #[serde(default = "default_false")]
    pub monero: bool,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            domains: true,
            ipv4: true,
            ipv6: true,
            emails: false,
            hashes: true,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }
    }
}

/// Configuration for the `matchy` transform.
#[configurable_component(transform(
    "matchy",
    "Match log events against threat intelligence databases."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct MatchyConfig {
    /// Map of database ID to database configuration
    ///
    /// Each database will be loaded and queried for matches. Results
    /// will be tagged with the database ID for downstream filtering.
    #[configurable(metadata(
        docs::additional_props_description = "Configuration for a matchy database."
    ))]
    pub databases: HashMap<String, DatabaseConfig>,

    /// Extraction configuration (optional)
    ///
    /// If specified, the transform will extract indicators (IPs, domains, etc.)
    /// from the specified field before matching. If not specified, the transform
    /// will attempt to match the entire field value.
    #[serde(default)]
    pub extract: Option<ExtractionConfig>,

    /// Field to read for matching (default: "message")
    #[serde(default = "default_source_field")]
    pub source_field: String,

    /// Field to write match results to (default: ".matchy_results")
    #[serde(default = "default_output_field")]
    pub output_field: String,

    /// Optional field to set as boolean match flag (e.g., ".is_threat")
    #[serde(default)]
    pub match_field: Option<String>,
}

fn default_source_field() -> String {
    "message".to_string()
}

fn default_output_field() -> String {
    ".matchy_results".to_string()
}

impl GenerateConfig for MatchyConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(
            r#"
            source_field = "message"
            output_field = ".matchy_results"
            match_field = ".is_threat"
            
            [databases.threats]
            path = "/data/threats.mxy"
            auto_reload = true
            
            [extract]
            domains = true
            ipv4 = true
            ipv6 = true
            "#,
        )
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "matchy")]
impl TransformConfig for MatchyConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        // Transform building is done in transform.rs
        super::transform::build_transform(self.clone())
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn outputs(
        &self,
        _enrichment_tables: vector_lib::enrichment::TableRegistry,
        input_definitions: &[(OutputId, schema::Definition)],
        _: LogNamespace,
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(
            DataType::Log,
            clone_input_definitions(input_definitions),
        )]
    }

    fn enable_concurrency(&self) -> bool {
        true
    }
}
