use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use vector_lib::event::{Event, LogEvent, Value};

use crate::{
    test_util::components::assert_transform_compliance,
    transforms::{
        matchy::config::{DatabaseConfig, ExtractionConfig, MatchyConfig},
        test::{create_topology, transform_one},
    },
};

use super::transform::MatchyTransform;

// Helper to create a simple test database with pattern matching
fn create_test_database() -> tempfile::NamedTempFile {
    use std::collections::HashMap;
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();

    // Use DatabaseBuilder with explicit APIs
    let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

    // Add literal domain names
    let mut data = HashMap::new();
    data.insert(
        "threat".to_string(),
        matchy::DataValue::String("known_bad".to_string()),
    );
    builder.add_literal("evil.com", data.clone()).unwrap();
    builder.add_literal("malware.org", data.clone()).unwrap();

    // Add glob pattern for wildcard matching
    builder.add_glob("*.badactor.net", data).unwrap();

    // Build and write
    let db_bytes = builder.build().unwrap();
    tmpfile.write_all(&db_bytes).unwrap();
    tmpfile.flush().unwrap();
    tmpfile
}

#[tokio::test]
async fn emits_internal_events() {
    assert_transform_compliance(async move {
        let tmpdb = create_test_database();

        let mut databases = HashMap::new();
        databases.insert(
            "test".to_string(),
            DatabaseConfig {
                path: tmpdb.path().to_string_lossy().to_string(),
                auto_reload: None,
            },
        );

        let config = MatchyConfig {
            databases,
            extract: None,
            source_field: "message".to_string(),
            output_field: ".matchy_results".to_string(),
            match_field: Some(".is_threat".to_string()),
        };

        let (tx, rx) = mpsc::channel(1);
        let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

        let log = LogEvent::from("Visit evil.com for details");
        tx.send(log.into()).await.unwrap();

        _ = out.recv().await;

        drop(tx);
        topology.stop().await;
        assert_eq!(out.recv().await, None);
    })
    .await
}

#[test]
fn remap_match_found() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        // Enable extraction to find "evil.com" within the message
        extract: Some(ExtractionConfig {
            domains: true,
            ipv4: false,
            ipv6: false,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: Some(".is_threat".to_string()),
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("Check out evil.com"));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    // Verify match flag is set
    assert_eq!(log.get(".is_threat"), Some(&Value::Boolean(true)));

    // Verify results array exists and has content
    let matches = log.get(".matchy_results").unwrap();
    assert!(matches.is_array());
    assert!(!matches.as_array().unwrap().is_empty());
}

#[test]
fn remap_no_match() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: Some(".is_threat".to_string()),
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("Nothing suspicious here"));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    // Verify no threat found
    assert_eq!(log.get(".is_threat"), Some(&Value::Boolean(false)));

    // Verify empty results array
    let matches = log.get(".matchy_results").unwrap();
    assert_eq!(matches.as_array().unwrap().len(), 0);
}

#[test]
fn remap_with_extraction() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: true,
            ipv4: false,
            ipv6: false,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from(
        "Traffic to evil.com and example.com detected",
    ));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    // Should have extracted and matched evil.com
    let matches = log.get(".matchy_results").unwrap();
    let matches_array = matches.as_array().unwrap();
    assert!(!matches_array.is_empty());

    // Verify match structure
    let first_match = matches_array[0].as_object().unwrap();
    assert_eq!(
        first_match.get("extracted_type").unwrap().as_str().unwrap(),
        "Domain"
    );
    assert!(first_match.contains_key("database_id"));
    assert!(first_match.contains_key("matched_text"));
}

#[test]
fn remap_custom_source_field() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "custom_field".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();

    let mut event = Event::Log(LogEvent::from("unrelated message"));
    event.as_mut_log().insert("custom_field", "evil.com");

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    // Should match from custom field
    let matches = log.get(".matchy_results").unwrap();
    assert!(!matches.as_array().unwrap().is_empty());
}

#[test]
fn remap_missing_source_field_passes_through() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "missing_field".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("message"));

    let result = transform_one(&mut transform, event.clone()).unwrap();

    // Should pass through unchanged when source field missing
    assert_eq!(result, event);
}

#[test]
fn remap_wildcard_pattern() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();

    // Should match *.badactor.net pattern
    let event = Event::Log(LogEvent::from("malicious.badactor.net"));
    let result = transform_one(&mut transform, event).unwrap();

    let matches = result.as_log().get(".matchy_results").unwrap();
    assert!(!matches.as_array().unwrap().is_empty());
}

#[test]
fn remap_multiple_databases() {
    let tmpdb1 = create_test_database();
    let tmpdb2 = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "db1".to_string(),
        DatabaseConfig {
            path: tmpdb1.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );
    databases.insert(
        "db2".to_string(),
        DatabaseConfig {
            path: tmpdb2.path().to_string_lossy().to_string(),
            auto_reload: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".matchy_results".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("evil.com"));

    let result = transform_one(&mut transform, event).unwrap();
    let matches = result.as_log().get(".matchy_results").unwrap();
    let matches_array = matches.as_array().unwrap();

    // Should have matches from both databases
    assert_eq!(matches_array.len(), 2);

    // Verify both database IDs present
    let db_ids: Vec<_> = matches_array
        .iter()
        .filter_map(|m| m.as_object().unwrap().get("database_id"))
        .map(|v| v.to_string_lossy())
        .collect();
    assert!(db_ids.iter().any(|id| id == "db1"));
    assert!(db_ids.iter().any(|id| id == "db2"));
}

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<MatchyConfig>();
}
