use std::{fs, path::PathBuf, sync::Arc, time::SystemTime};

use matchy::{Database, QueryResult};
use vector_lib::{
    configurable::configurable_component,
    enrichment::{Case, Condition, IndexHandle, Table},
};
use vrl::value::{ObjectMap, Value};

use crate::config::{EnrichmentTableConfig, GenerateConfig};

#[derive(Clone, Debug, Eq, PartialEq)]
#[configurable_component(enrichment_table("matchy"))]
pub struct MatchyConfig {
    pub path: PathBuf,
}

impl GenerateConfig for MatchyConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            path: "/path/to/threats.mxy".into(),
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

#[derive(Clone)]
pub struct Matchy {
    config: MatchyConfig,
    database: Arc<Database>,
    last_modified: SystemTime,
}

impl Matchy {
    pub fn new(config: MatchyConfig) -> crate::Result<Self> {
        let database = Arc::new(
            Database::from(&config.path)
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
}
