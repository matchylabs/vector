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
                auto_update: None,
                update_interval_secs: None,
                cache_dir: None,
                cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );
    databases.insert(
        "db2".to_string(),
        DatabaseConfig {
            path: tmpdb2.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
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
fn remap_direct_field_lookup() {
    // Test direct field lookup without extraction (customer routing use case)
    use std::collections::HashMap;
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();

    // Create database with IP → customer mapping
    let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

    // Add customer IP ranges with customer names as data
    let mut customer_a_data = HashMap::new();
    customer_a_data.insert(
        "customer".to_string(),
        matchy::DataValue::String("customer_a".to_string()),
    );
    customer_a_data.insert(
        "tier".to_string(),
        matchy::DataValue::String("premium".to_string()),
    );

    let mut customer_b_data = HashMap::new();
    customer_b_data.insert(
        "customer".to_string(),
        matchy::DataValue::String("customer_b".to_string()),
    );
    customer_b_data.insert(
        "tier".to_string(),
        matchy::DataValue::String("standard".to_string()),
    );

    builder.add_ip("192.168.1.0/24", customer_a_data).unwrap();
    builder.add_ip("10.0.0.0/24", customer_b_data).unwrap();

    let db_bytes = builder.build().unwrap();
    tmpfile.write_all(&db_bytes).unwrap();
    tmpfile.flush().unwrap();

    let mut databases = HashMap::new();
    databases.insert(
        "customers".to_string(),
        DatabaseConfig {
            path: tmpfile.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None, // No extraction - direct field lookup
        source_field: "client_ip".to_string(),
        output_field: ".customer_info".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();

    // Create event with parsed client_ip field
    let mut event = Event::Log(LogEvent::from("some message"));
    event.as_mut_log().insert("client_ip", "192.168.1.42");

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    // Should have customer info
    let customer_info = log.get(".customer_info").unwrap();
    let matches = customer_info.as_array().unwrap();
    assert_eq!(matches.len(), 1);

    // Verify customer data
    let match_obj = matches[0].as_object().unwrap();
    let data = match_obj.get("data").unwrap().as_object().unwrap();
    assert_eq!(
        data.get("customer").unwrap().as_str().unwrap(),
        "customer_a"
    );
    assert_eq!(data.get("tier").unwrap().as_str().unwrap(), "premium");
    assert_eq!(
        match_obj.get("database_id").unwrap().as_str().unwrap(),
        "customers"
    );
    assert_eq!(
        match_obj.get("matched_text").unwrap().as_str().unwrap(),
        "192.168.1.42"
    );
}

#[test]
fn remap_direct_field_lookup_no_match() {
    use std::collections::HashMap;
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

    let mut data = HashMap::new();
    data.insert(
        "customer".to_string(),
        matchy::DataValue::String("test".to_string()),
    );
    builder.add_ip("192.168.1.0/24", data).unwrap();

    let db_bytes = builder.build().unwrap();
    tmpfile.write_all(&db_bytes).unwrap();
    tmpfile.flush().unwrap();

    let mut databases = HashMap::new();
    databases.insert(
        "customers".to_string(),
        DatabaseConfig {
            path: tmpfile.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "client_ip".to_string(),
        output_field: ".customer_info".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();

    // IP not in any customer range
    let mut event = Event::Log(LogEvent::from("some message"));
    event.as_mut_log().insert("client_ip", "203.0.113.1");

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    // Should have empty array (no match)
    let customer_info = log.get(".customer_info").unwrap();
    assert_eq!(customer_info.as_array().unwrap().len(), 0);
}

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<MatchyConfig>();
}

fn create_ip_threat_database() -> tempfile::NamedTempFile {
    use std::collections::HashMap;
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

    let mut malicious_data = HashMap::new();
    malicious_data.insert(
        "threat_type".to_string(),
        matchy::DataValue::String("malware_c2".to_string()),
    );
    malicious_data.insert(
        "severity".to_string(),
        matchy::DataValue::String("critical".to_string()),
    );

    builder
        .add_ip("10.0.0.0/8", malicious_data.clone())
        .unwrap();
    builder.add_ip("192.168.100.0/24", malicious_data).unwrap();

    let db_bytes = builder.build().unwrap();
    tmpfile.write_all(&db_bytes).unwrap();
    tmpfile.flush().unwrap();
    tmpfile
}

#[test]
fn extract_ipv4_and_lookup() {
    let tmpdb = create_ip_threat_database();

    let mut databases = HashMap::new();
    databases.insert(
        "threats".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: false,
            ipv4: true,
            ipv6: false,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".threats".to_string(),
        match_field: Some(".is_malicious".to_string()),
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("Connection from 10.20.30.40 detected"));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    assert_eq!(log.get(".is_malicious"), Some(&Value::Boolean(true)));

    let threats = log.get(".threats").unwrap().as_array().unwrap();
    assert_eq!(threats.len(), 1);

    let threat = threats[0].as_object().unwrap();
    assert_eq!(
        threat.get("matched_text").unwrap().as_str().unwrap(),
        "10.20.30.40"
    );
    assert_eq!(
        threat.get("extracted_type").unwrap().as_str().unwrap(),
        "IPv4"
    );
    assert_eq!(threat.get("match_type").unwrap().as_str().unwrap(), "ip");

    let data = threat.get("data").unwrap().as_object().unwrap();
    assert_eq!(
        data.get("threat_type").unwrap().as_str().unwrap(),
        "malware_c2"
    );
    assert_eq!(data.get("severity").unwrap().as_str().unwrap(), "critical");
}

#[test]
fn extract_ipv4_no_threat_match() {
    let tmpdb = create_ip_threat_database();

    let mut databases = HashMap::new();
    databases.insert(
        "threats".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: false,
            ipv4: true,
            ipv6: false,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".threats".to_string(),
        match_field: Some(".is_malicious".to_string()),
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("Safe connection from 8.8.8.8"));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    assert_eq!(log.get(".is_malicious"), Some(&Value::Boolean(false)));
    assert!(log.get(".threats").unwrap().as_array().unwrap().is_empty());
}

#[test]
fn extract_multiple_ipv4_addresses() {
    let tmpdb = create_ip_threat_database();

    let mut databases = HashMap::new();
    databases.insert(
        "threats".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: false,
            ipv4: true,
            ipv6: false,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".threats".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from(
        "Traffic: 10.1.2.3 -> 192.168.100.50 via 8.8.8.8",
    ));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    let threats = log.get(".threats").unwrap().as_array().unwrap();
    assert_eq!(threats.len(), 2);

    let matched_ips: Vec<String> = threats
        .iter()
        .map(|t| {
            t.as_object()
                .unwrap()
                .get("matched_text")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(matched_ips.contains(&"10.1.2.3".to_string()));
    assert!(matched_ips.contains(&"192.168.100.50".to_string()));
}

fn create_ipv6_threat_database() -> tempfile::NamedTempFile {
    use std::collections::HashMap;
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

    let mut threat_data = HashMap::new();
    threat_data.insert(
        "category".to_string(),
        matchy::DataValue::String("botnet".to_string()),
    );

    builder.add_ip("2001:db8::/32", threat_data).unwrap();

    let db_bytes = builder.build().unwrap();
    tmpfile.write_all(&db_bytes).unwrap();
    tmpfile.flush().unwrap();
    tmpfile
}

#[test]
fn extract_ipv6_and_lookup() {
    let tmpdb = create_ipv6_threat_database();

    let mut databases = HashMap::new();
    databases.insert(
        "threats".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: false,
            ipv4: false,
            ipv6: true,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".threats".to_string(),
        match_field: Some(".is_threat".to_string()),
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("Connection from 2001:db8::1234 detected"));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    assert_eq!(log.get(".is_threat"), Some(&Value::Boolean(true)));

    let threats = log.get(".threats").unwrap().as_array().unwrap();
    assert_eq!(threats.len(), 1);

    let threat = threats[0].as_object().unwrap();
    assert_eq!(
        threat.get("matched_text").unwrap().as_str().unwrap(),
        "2001:db8::1234"
    );
    assert_eq!(
        threat.get("extracted_type").unwrap().as_str().unwrap(),
        "IPv6"
    );

    let data = threat.get("data").unwrap().as_object().unwrap();
    assert_eq!(data.get("category").unwrap().as_str().unwrap(), "botnet");
}

#[test]
fn extract_ipv6_no_match() {
    let tmpdb = create_ipv6_threat_database();

    let mut databases = HashMap::new();
    databases.insert(
        "threats".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: false,
            ipv4: false,
            ipv6: true,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".threats".to_string(),
        match_field: Some(".is_threat".to_string()),
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from("Connection from ::1 (localhost)"));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    assert_eq!(log.get(".is_threat"), Some(&Value::Boolean(false)));
}

#[test]
fn extract_mixed_ipv4_and_ipv6() {
    use std::collections::HashMap as StdHashMap;
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    let mut builder = matchy::DatabaseBuilder::new(matchy::MatchMode::CaseInsensitive);

    let mut v4_data = StdHashMap::new();
    v4_data.insert(
        "source".to_string(),
        matchy::DataValue::String("ipv4_feed".to_string()),
    );
    builder.add_ip("10.0.0.0/8", v4_data).unwrap();

    let mut v6_data = StdHashMap::new();
    v6_data.insert(
        "source".to_string(),
        matchy::DataValue::String("ipv6_feed".to_string()),
    );
    builder.add_ip("2001:db8::/32", v6_data).unwrap();

    let db_bytes = builder.build().unwrap();
    tmpfile.write_all(&db_bytes).unwrap();
    tmpfile.flush().unwrap();

    let mut databases = HashMap::new();
    databases.insert(
        "threats".to_string(),
        DatabaseConfig {
            path: tmpfile.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: Some(ExtractionConfig {
            domains: false,
            ipv4: true,
            ipv6: true,
            emails: false,
            hashes: false,
            bitcoin: false,
            ethereum: false,
            monero: false,
        }),
        source_field: "message".to_string(),
        output_field: ".threats".to_string(),
        match_field: None,
    };

    let mut transform = MatchyTransform::new(config).unwrap();
    let event = Event::Log(LogEvent::from(
        "Dual-stack: 10.50.60.70 and 2001:db8::abcd both flagged",
    ));

    let result = transform_one(&mut transform, event).unwrap();
    let log = result.as_log();

    let threats = log.get(".threats").unwrap().as_array().unwrap();
    assert_eq!(threats.len(), 2);

    let sources: Vec<String> = threats
        .iter()
        .map(|t| {
            t.as_object()
                .unwrap()
                .get("data")
                .unwrap()
                .as_object()
                .unwrap()
                .get("source")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(sources.contains(&"ipv4_feed".to_string()));
    assert!(sources.contains(&"ipv6_feed".to_string()));
}

#[test]
fn error_invalid_database_path() {
    let mut databases = HashMap::new();
    databases.insert(
        "bad".to_string(),
        DatabaseConfig {
            path: "/nonexistent/path/to/database.mxy".to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".results".to_string(),
        match_field: None,
    };

    let result = MatchyTransform::new(config);
    assert!(result.is_err());

    let err_msg = format!("{}", result.err().unwrap());
    assert!(err_msg.contains("Failed to open database"));
}

#[test]
fn error_corrupted_database() {
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(b"not a valid matchy database").unwrap();
    tmpfile.flush().unwrap();

    let mut databases = HashMap::new();
    databases.insert(
        "corrupted".to_string(),
        DatabaseConfig {
            path: tmpfile.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".results".to_string(),
        match_field: None,
    };

    let result = MatchyTransform::new(config);
    assert!(result.is_err());
}

#[test]
fn error_empty_database_file() {
    use std::io::Write;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(b"").unwrap();
    tmpfile.flush().unwrap();

    let mut databases = HashMap::new();
    databases.insert(
        "empty".to_string(),
        DatabaseConfig {
            path: tmpfile.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: None,
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".results".to_string(),
        match_field: None,
    };

    let result = MatchyTransform::new(config);
    assert!(result.is_err());
}

#[test]
fn config_with_cache_disabled() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: Some(0),
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".results".to_string(),
        match_field: None,
    };

    let result = MatchyTransform::new(config);
    assert!(result.is_ok());
}

#[test]
fn config_with_custom_cache_capacity() {
    let tmpdb = create_test_database();

    let mut databases = HashMap::new();
    databases.insert(
        "test".to_string(),
        DatabaseConfig {
            path: tmpdb.path().to_string_lossy().to_string(),
            auto_reload: None,
            auto_update: None,
            update_interval_secs: None,
            cache_dir: None,
            cache_capacity: Some(5000),
        },
    );

    let config = MatchyConfig {
        databases,
        extract: None,
        source_field: "message".to_string(),
        output_field: ".results".to_string(),
        match_field: None,
    };

    let result = MatchyTransform::new(config);
    assert!(result.is_ok());
}
