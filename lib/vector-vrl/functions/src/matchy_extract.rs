use vrl::prelude::*;

#[derive(Clone, Copy, Debug)]
pub struct MatchyExtract;

impl Function for MatchyExtract {
    fn identifier(&self) -> &'static str {
        "matchy_extract"
    }

    fn parameters(&self) -> &'static [Parameter] {
        &[
            Parameter {
                keyword: "text",
                kind: kind::BYTES,
                required: true,
            },
            Parameter {
                keyword: "types",
                kind: kind::ARRAY,
                required: false,
            },
        ]
    }

    fn examples(&self) -> &'static [Example] {
        &[
            example!(
                title: "extract IPs and domains",
                source: r#"matchy_extract("Server 1.2.3.4 contacted evil.com", types: ["ipv4", "domains"])"#,
                result: Ok(
                    r#"[{"type": "ipv4", "value": "1.2.3.4"}, {"type": "domain", "value": "evil.com"}]"#,
                ),
            ),
            example!(
                title: "extract all IOC types (default)",
                source: r#"matchy_extract("Hash: abc123def456 from 10.0.0.1")"#,
                result: Ok(r#"[{"type": "ipv4", "value": "10.0.0.1"}]"#),
            ),
        ]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let text = arguments.required("text");
        let types = arguments.optional("types");

        Ok(MatchyExtractFn { text, types }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct MatchyExtractFn {
    text: Box<dyn Expression>,
    types: Option<Box<dyn Expression>>,
}

impl FunctionExpression for MatchyExtractFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let text = self.text.resolve(ctx)?;
        let text_bytes = text.try_bytes_utf8_lossy()?;

        let extract_types = if let Some(ref types_expr) = self.types {
            let types_value = types_expr.resolve(ctx)?;
            let types_array = types_value.try_array()?;

            let mut types = Vec::new();
            for type_val in types_array.iter() {
                types.push(type_val.try_bytes_utf8_lossy()?.to_string());
            }
            types
        } else {
            vec![
                "ipv4".to_string(),
                "ipv6".to_string(),
                "domains".to_string(),
            ]
        };

        let mut builder = matchy::extractor::ExtractorBuilder::new();

        for extract_type in &extract_types {
            match extract_type.as_str() {
                "ipv4" => builder = builder.extract_ipv4(true),
                "ipv6" => builder = builder.extract_ipv6(true),
                "domains" => builder = builder.extract_domains(true),
                "emails" => builder = builder.extract_emails(true),
                "hashes" => builder = builder.extract_hashes(true),
                "bitcoin" => builder = builder.extract_bitcoin(true),
                "ethereum" => builder = builder.extract_ethereum(true),
                "monero" => builder = builder.extract_monero(true),
                _ => {
                    return Err(format!("unknown extraction type: {}", extract_type).into());
                }
            }
        }

        let extractor = builder
            .build()
            .map_err(|e| format!("failed to build extractor: {}", e))?;

        let mut results = Vec::new();
        for item in extractor.extract_from_line(text_bytes.as_bytes()) {
            let mut map = ObjectMap::new();

            map.insert("type".into(), item.item.type_name().into());

            let value_str = item.as_str(text_bytes.as_bytes());
            map.insert("value".into(), value_str.into());

            map.insert("start".into(), (item.span.0 as i64).into());
            map.insert("end".into(), (item.span.1 as i64).into());

            results.push(Value::Object(map));
        }

        Ok(Value::Array(results))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::array(Collection::from_unknown(Kind::object(Collection::any()))).fallible()
    }
}

#[cfg(all(test, feature = "enrichment-tables-matchy"))]
mod tests {
    fn extract(text: &str, types: &[&str]) -> Vec<(String, String)> {
        let mut builder = matchy::extractor::ExtractorBuilder::new();

        for t in types {
            builder = match *t {
                "ipv4" => builder.extract_ipv4(true),
                "ipv6" => builder.extract_ipv6(true),
                "domains" => builder.extract_domains(true),
                "emails" => builder.extract_emails(true),
                "hashes" => builder.extract_hashes(true),
                "bitcoin" => builder.extract_bitcoin(true),
                "ethereum" => builder.extract_ethereum(true),
                "monero" => builder.extract_monero(true),
                _ => builder,
            };
        }

        let extractor = builder.build().unwrap();
        extractor
            .extract_from_line(text.as_bytes())
            .map(|item| {
                (
                    item.item.type_name().to_string(),
                    item.as_str(text.as_bytes()).to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_extract_ipv4() {
        let results = extract("Server at 192.168.1.1 responded", &["ipv4"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ("IPv4".to_string(), "192.168.1.1".to_string()));
    }

    #[test]
    fn test_extract_multiple_ipv4() {
        let results = extract("From 10.0.0.1 to 10.0.0.2 via 10.0.0.254", &["ipv4"]);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].1, "10.0.0.1");
        assert_eq!(results[1].1, "10.0.0.2");
        assert_eq!(results[2].1, "10.0.0.254");
    }

    #[test]
    fn test_extract_ipv6() {
        let results = extract("Connected to 2001:db8::1 successfully", &["ipv6"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ("IPv6".to_string(), "2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_domain() {
        let results = extract("Visit example.com for more info", &["domains"]);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            ("Domain".to_string(), "example.com".to_string())
        );
    }

    #[test]
    fn test_extract_subdomain() {
        let results = extract("API endpoint: api.staging.example.com", &["domains"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "api.staging.example.com");
    }

    #[test]
    fn test_extract_email() {
        let results = extract("Contact: user@example.com for help", &["emails"]);
        assert!(!results.is_empty());

        let emails: Vec<_> = results.iter().filter(|(t, _)| t == "Email").collect();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].1, "user@example.com");
    }

    #[test]
    fn test_extract_ipv6_full() {
        let results = extract("Address: 2001:db8:85a3::8a2e:370:7334", &["ipv6"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "IPv6");
    }

    #[test]
    fn test_extract_sha256_hash() {
        let results = extract(
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &["hashes"],
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "SHA256");
    }

    #[test]
    fn test_extract_mixed_types() {
        let results = extract(
            "Server 192.168.1.1 at evil.com sent email to admin@corp.com",
            &["ipv4", "domains", "emails"],
        );

        let types: Vec<_> = results.iter().map(|(t, _)| t.as_str()).collect();
        assert!(types.contains(&"IPv4"));
        assert!(types.contains(&"Domain"));
        assert!(types.contains(&"Email"));
    }

    #[test]
    fn test_extract_no_matches() {
        let results = extract("Just some regular text here", &["ipv4", "domains"]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_default_types() {
        let results = extract(
            "Server 10.0.0.1 and 2001:db8::1 at example.com",
            &["ipv4", "ipv6", "domains"],
        );
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_extract_preserves_position() {
        let text = "IP: 1.2.3.4";
        let extractor = matchy::extractor::ExtractorBuilder::new()
            .extract_ipv4(true)
            .build()
            .unwrap();

        let items: Vec<_> = extractor.extract_from_line(text.as_bytes()).collect();
        assert_eq!(items.len(), 1);

        let expected_start = text.find("1.2.3.4").unwrap();
        let expected_end = expected_start + "1.2.3.4".len();
        assert_eq!(items[0].span.0, expected_start);
        assert_eq!(items[0].span.1, expected_end);
    }
}
