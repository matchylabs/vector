use std::{fs, path::PathBuf, sync::Arc, time::Duration, time::SystemTime};

use matchy::{Database, QueryResult};
use vector_lib::{
    configurable::configurable_component,
    enrichment::{Case, Condition, IndexHandle, Table},
};
use vrl::value::{ObjectMap, Value};

use crate::config::{EnrichmentTableConfig, GenerateConfig};

/// Configuration for the `matchy` enrichment table.
#[derive(Clone, Debug, Eq, PartialEq)]
#[configurable_component(enrichment_table("matchy"))]
pub struct MatchyConfig {
    /// Path to the Matchy database file (.mxy) or MaxMind database (.mmdb).
    pub path: PathBuf,

    /// Enable automatic reload when the database file changes.
    #[serde(default)]
    pub auto_reload: Option<bool>,

    /// Enable automatic updates from the database's embedded update URL.
    #[serde(default)]
    pub auto_update: Option<bool>,

    /// How often to check for remote updates (in seconds).
    #[serde(default)]
    pub update_interval_secs: Option<u64>,

    /// Directory to cache downloaded database updates.
    #[serde(default)]
    pub cache_dir: Option<String>,

    /// LRU cache capacity for query results (0 to disable).
    #[serde(default)]
    pub cache_capacity: Option<usize>,
}

impl GenerateConfig for MatchyConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            path: "/path/to/threats.mxy".into(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        })
        .unwrap()
    }
}

impl EnrichmentTableConfig for MatchyConfig {
    async fn build(
        &self,
        _: &crate::config::GlobalOptions,
    ) -> crate::Result<Box<dyn Table + Send + Sync>> {
        Ok(Box::new(Matchy::new(self.clone())?))
    }
}

/// Matchy enrichment table implementation.
#[derive(Clone)]
pub struct Matchy {
    config: MatchyConfig,
    database: Arc<Database>,
    last_modified: SystemTime,
}

impl Matchy {
    /// Creates a new Matchy enrichment table from configuration.
    pub fn new(config: MatchyConfig) -> crate::Result<Self> {
        let mut opener = Database::from(&config.path);

        if let Some(capacity) = config.cache_capacity {
            if capacity == 0 {
                opener = opener.no_cache();
            } else {
                opener = opener.cache_capacity(capacity);
            }
        }

        if config.auto_reload.unwrap_or(false) {
            opener = opener.watch();
        }

        if config.auto_update.unwrap_or(false) {
            opener = opener.auto_update();

            if let Some(interval_secs) = config.update_interval_secs {
                opener = opener.update_interval(Duration::from_secs(interval_secs));
            }

            if let Some(ref dir) = config.cache_dir {
                opener = opener.cache_dir(dir);
            }
        }

        let database = Arc::new(
            opener
                .open()
                .map_err(|e| format!("Failed to open matchy database: {}", e))?,
        );

        Ok(Matchy {
            last_modified: fs::metadata(&config.path)?.modified()?,
            database,
            config,
        })
    }

    fn lookup(&self, text: &str, select: Option<&[String]>) -> Option<ObjectMap> {
        let result = self.database.lookup(text).ok()??;

        let data_json = match result {
            QueryResult::Ip { data, .. } => serde_json::to_value(&data).ok()?,
            QueryResult::Pattern { data, .. } => {
                let first_data = data.into_iter().find_map(|d| d)?;
                serde_json::to_value(&first_data).ok()?
            }
            QueryResult::NotFound => return None,
        };

        let object_map = match data_json {
            serde_json::Value::Object(map) => {
                let mut vrl_map = ObjectMap::new();
                for (k, v) in map {
                    vrl_map.insert(k.into(), json_to_vrl_value(v));
                }
                vrl_map
            }
            _ => return None,
        };

        if let Some(fields) = select {
            let mut filtered = ObjectMap::new();
            for field in fields {
                if let Some(value) = get_nested_value(&object_map, field) {
                    set_nested_value(&mut filtered, field, value);
                }
            }
            return Some(filtered);
        }

        Some(object_map)
    }
}

fn json_to_vrl_value(json: serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(
                    ordered_float::NotNan::new(f)
                        .unwrap_or(ordered_float::NotNan::new(0.0).unwrap()),
                )
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::Bytes(s.into()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.into_iter().map(json_to_vrl_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut map = ObjectMap::new();
            for (k, v) in obj {
                map.insert(k.into(), json_to_vrl_value(v));
            }
            Value::Object(map)
        }
    }
}

fn get_nested_value(map: &ObjectMap, path: &str) -> Option<Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = Value::Object(map.clone());

    for part in parts {
        match current {
            Value::Object(ref obj) => {
                current = obj.get(part)?.clone();
            }
            _ => return None,
        }
    }

    Some(current)
}

fn set_nested_value(map: &mut ObjectMap, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.len() == 1 {
        map.insert(path.into(), value);
        return;
    }

    let mut current_value = value;
    for part in parts.iter().rev() {
        let mut nested_map = ObjectMap::new();
        nested_map.insert((*part).into(), current_value);
        current_value = Value::Object(nested_map);
    }

    if let Value::Object(mut outer) = current_value {
        if let Some((key, val)) = outer.iter_mut().next() {
            map.insert(key.clone(), val.clone());
        }
    }
}

impl Table for Matchy {
    fn find_table_row<'a>(
        &self,
        case: Case,
        condition: &'a [Condition<'a>],
        select: Option<&[String]>,
        wildcard: Option<&Value>,
        index: Option<IndexHandle>,
    ) -> Result<ObjectMap, String> {
        let mut rows = self.find_table_rows(case, condition, select, wildcard, index)?;

        match rows.pop() {
            Some(row) if rows.is_empty() => Ok(row),
            Some(_) => Err("More than 1 row found".to_string()),
            None => Err("No match found".to_string()),
        }
    }

    fn find_table_rows<'a>(
        &self,
        _: Case,
        condition: &'a [Condition<'a>],
        select: Option<&[String]>,
        _wildcard: Option<&Value>,
        _: Option<IndexHandle>,
    ) -> Result<Vec<ObjectMap>, String> {
        match condition.first() {
            Some(_) if condition.len() > 1 => Err("Only one condition is allowed".to_string()),
            Some(Condition::Equals { value, .. }) => {
                let text = value.to_string_lossy();
                Ok(self
                    .lookup(&text, select)
                    .map(|values| vec![values])
                    .unwrap_or_default())
            }
            Some(_) => Err("Only equality condition is allowed".to_string()),
            None => Err("Lookup condition must be specified".to_string()),
        }
    }

    fn add_index(&mut self, _: Case, fields: &[&str]) -> Result<IndexHandle, String> {
        match fields.len() {
            0 => Err("Lookup field is required".to_string()),
            1 => Ok(IndexHandle(0)),
            _ => Err("Only one field is allowed".to_string()),
        }
    }

    fn index_fields(&self) -> Vec<(Case, Vec<String>)> {
        Vec::new()
    }

    fn needs_reload(&self) -> bool {
        matches!(fs::metadata(&self.config.path)
            .and_then(|metadata| metadata.modified()),
            Ok(modified) if modified > self.last_modified)
    }
}

impl std::fmt::Debug for Matchy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Matchy database {})", self.config.path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vector_lib::enrichment::{Case, Condition};
    use vrl::value::Value;

    #[test]
    fn test_json_to_vrl_conversion() {
        let json = serde_json::json!({
            "city": "London",
            "latitude": 51.5074,
            "population": 8_982_000
        });

        let vrl_value = json_to_vrl_value(json);

        match vrl_value {
            Value::Object(map) => {
                assert_eq!(map.get("city").unwrap(), &Value::Bytes("London".into()));
                assert_eq!(
                    map.get("latitude").unwrap(),
                    &Value::Float(ordered_float::NotNan::new(51.5074).unwrap())
                );
                assert_eq!(map.get("population").unwrap(), &Value::Integer(8_982_000));
            }
            _ => panic!("Expected object"),
        }
    }

    #[test]
    fn test_get_nested_value() {
        let mut map = ObjectMap::new();
        let mut location = ObjectMap::new();
        location.insert(
            "latitude".into(),
            Value::Float(ordered_float::NotNan::new(51.5).unwrap()),
        );
        location.insert(
            "longitude".into(),
            Value::Float(ordered_float::NotNan::new(-0.1).unwrap()),
        );
        map.insert("location".into(), Value::Object(location));

        let value = get_nested_value(&map, "location.latitude");
        assert_eq!(
            value,
            Some(Value::Float(ordered_float::NotNan::new(51.5).unwrap()))
        );
    }

    fn create_test_matchy_db() -> tempfile::NamedTempFile {
        use std::collections::HashMap;
        use std::io::Write;

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

        let mut threat_data = HashMap::new();
        threat_data.insert(
            "category".to_string(),
            matchy::DataValue::String("malware".to_string()),
        );
        threat_data.insert(
            "severity".to_string(),
            matchy::DataValue::String("high".to_string()),
        );

        builder.add_ip("10.0.0.0/8", threat_data.clone()).unwrap();
        builder.add_literal("evil.com", threat_data).unwrap();

        let db_bytes = builder.build().unwrap();
        tmpfile.write_all(&db_bytes).unwrap();
        tmpfile.flush().unwrap();
        tmpfile
    }

    #[test]
    fn test_enrichment_table_ip_lookup() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let condition = [Condition::Equals {
            field: "ip",
            value: Value::from("10.20.30.40"),
        }];

        let result = table.find_table_rows(Case::Sensitive, &condition, None, None, None);
        assert!(result.is_ok());

        let rows = result.unwrap();
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert_eq!(
            row.get("category").unwrap(),
            &Value::Bytes("malware".into())
        );
        assert_eq!(row.get("severity").unwrap(), &Value::Bytes("high".into()));
    }

    #[test]
    fn test_enrichment_table_pattern_lookup() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let condition = [Condition::Equals {
            field: "text",
            value: Value::from("evil.com"),
        }];

        let result = table.find_table_rows(Case::Sensitive, &condition, None, None, None);
        assert!(result.is_ok());

        let rows = result.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("category").unwrap(),
            &Value::Bytes("malware".into())
        );
    }

    #[test]
    fn test_enrichment_table_no_match() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let condition = [Condition::Equals {
            field: "ip",
            value: Value::from("8.8.8.8"),
        }];

        let result = table.find_table_rows(Case::Sensitive, &condition, None, None, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_enrichment_table_find_single_row() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let condition = [Condition::Equals {
            field: "ip",
            value: Value::from("10.0.0.1"),
        }];

        let result = table.find_table_row(Case::Sensitive, &condition, None, None, None);
        assert!(result.is_ok());

        let row = result.unwrap();
        assert_eq!(
            row.get("category").unwrap(),
            &Value::Bytes("malware".into())
        );
    }

    #[test]
    fn test_enrichment_table_find_row_no_match() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let condition = [Condition::Equals {
            field: "ip",
            value: Value::from("8.8.8.8"),
        }];

        let result = table.find_table_row(Case::Sensitive, &condition, None, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No match found");
    }

    #[test]
    fn test_enrichment_table_add_index() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let mut table = Matchy::new(config).unwrap();

        let result = table.add_index(Case::Sensitive, &["ip"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_enrichment_table_add_index_no_field() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let mut table = Matchy::new(config).unwrap();

        let result = table.add_index(Case::Sensitive, &[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Lookup field is required");
    }

    #[test]
    fn test_enrichment_table_add_index_multiple_fields() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let mut table = Matchy::new(config).unwrap();

        let result = table.add_index(Case::Sensitive, &["ip", "domain"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Only one field is allowed");
    }

    #[test]
    fn test_enrichment_table_multiple_conditions_error() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let conditions = [
            Condition::Equals {
                field: "ip",
                value: Value::from("10.0.0.1"),
            },
            Condition::Equals {
                field: "domain",
                value: Value::from("evil.com"),
            },
        ];

        let result = table.find_table_rows(Case::Sensitive, &conditions, None, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Only one condition is allowed");
    }

    #[test]
    fn test_enrichment_table_no_condition_error() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let result = table.find_table_rows(Case::Sensitive, &[], None, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Lookup condition must be specified");
    }

    #[test]
    fn test_enrichment_table_needs_reload() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        assert!(!table.needs_reload());
    }

    #[test]
    fn test_enrichment_table_with_select() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let table = Matchy::new(config).unwrap();

        let condition = [Condition::Equals {
            field: "ip",
            value: Value::from("10.0.0.1"),
        }];

        let select = vec!["category".to_string()];
        let result = table.find_table_rows(Case::Sensitive, &condition, Some(&select), None, None);
        assert!(result.is_ok());

        let rows = result.unwrap();
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert!(row.contains_key("category"));
        assert!(!row.contains_key("severity"));
    }

    #[test]
    fn test_enrichment_table_invalid_path() {
        let config = MatchyConfig {
            path: "/nonexistent/database.mxy".into(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let result = Matchy::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_enrichment_table_corrupted_file() {
        use std::io::Write;

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"invalid data").unwrap();
        tmpfile.flush().unwrap();

        let config = MatchyConfig {
            path: tmpfile.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        };

        let result = Matchy::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_enrichment_table_cache_disabled() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: Some(0),
        };

        let table = Matchy::new(config);
        assert!(table.is_ok());
    }

    #[test]
    fn test_enrichment_table_custom_cache() {
        let tmpdb = create_test_matchy_db();
        let config = MatchyConfig {
            path: tmpdb.path().to_path_buf(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: Some(1000),
        };

        let table = Matchy::new(config);
        assert!(table.is_ok());
    }

    #[test]
    fn test_json_to_vrl_null() {
        let json = serde_json::Value::Null;
        assert_eq!(json_to_vrl_value(json), Value::Null);
    }

    #[test]
    fn test_json_to_vrl_bool() {
        assert_eq!(
            json_to_vrl_value(serde_json::json!(true)),
            Value::Boolean(true)
        );
        assert_eq!(
            json_to_vrl_value(serde_json::json!(false)),
            Value::Boolean(false)
        );
    }

    #[test]
    fn test_json_to_vrl_array() {
        let json = serde_json::json!([1, 2, 3]);
        let result = json_to_vrl_value(json);

        match result {
            Value::Array(arr) => {
                assert_eq!(arr.len(), 3);
                assert_eq!(arr[0], Value::Integer(1));
                assert_eq!(arr[1], Value::Integer(2));
                assert_eq!(arr[2], Value::Integer(3));
            }
            _ => panic!("Expected array"),
        }
    }

    #[test]
    fn test_json_to_vrl_nested_object() {
        let json = serde_json::json!({
            "outer": {
                "inner": "value"
            }
        });

        let result = json_to_vrl_value(json);

        match result {
            Value::Object(map) => {
                let outer = map.get("outer").unwrap();
                match outer {
                    Value::Object(inner_map) => {
                        assert_eq!(
                            inner_map.get("inner").unwrap(),
                            &Value::Bytes("value".into())
                        );
                    }
                    _ => panic!("Expected nested object"),
                }
            }
            _ => panic!("Expected object"),
        }
    }
}
