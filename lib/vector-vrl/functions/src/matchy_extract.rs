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
            Example {
                title: "extract IPs and domains",
                source: r#"matchy_extract("Server 1.2.3.4 contacted evil.com", types: ["ipv4", "domains"])"#,
                result: Ok(
                    r#"[{"type": "ipv4", "value": "1.2.3.4"}, {"type": "domain", "value": "evil.com"}]"#,
                ),
            },
            Example {
                title: "extract all IOC types (default)",
                source: r#"matchy_extract("Hash: abc123def456 from 10.0.0.1")"#,
                result: Ok(r#"[{"type": "ipv4", "value": "10.0.0.1"}]"#),
            },
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

#[cfg(test)]
mod tests {
    use super::*;
    use vrl::compiler::{TargetValue, TimeZone};
    use vrl::value::Secrets;

    #[test]
    fn extract_ipv4() {
        let mut object = ObjectMap::new();
        object.insert("message".into(), "Server at 1.2.3.4 responded".into());
        let mut target = TargetValue {
            value: Value::Object(object),
            metadata: Value::Object(ObjectMap::new()),
            secrets: Secrets::default(),
        };
        let mut ctx = Context::new(&mut target, &TimeZone::default());

        let func = MatchyExtractFn {
            text: Box::new(Literal::from("Server at 1.2.3.4 responded")),
            types: Some(Box::new(Literal::from(vec!["ipv4"]))),
        };

        let result = func.resolve(&mut ctx).unwrap();
        let array = result.as_array().unwrap();

        assert_eq!(array.len(), 1);
        let first = array[0].as_object().unwrap();
        assert_eq!(first.get("type").unwrap().as_bytes().unwrap(), b"ipv4");
        assert_eq!(first.get("value").unwrap().as_bytes().unwrap(), b"1.2.3.4");
    }

    #[test]
    fn extract_domain() {
        let mut object = ObjectMap::new();
        object.insert("message".into(), "Connected to evil.com".into());
        let mut target = TargetValue {
            value: Value::Object(object),
            metadata: Value::Object(ObjectMap::new()),
            secrets: Secrets::default(),
        };
        let mut ctx = Context::new(&mut target, &TimeZone::default());

        let func = MatchyExtractFn {
            text: Box::new(Literal::from("Connected to evil.com")),
            types: Some(Box::new(Literal::from(vec!["domains"]))),
        };

        let result = func.resolve(&mut ctx).unwrap();
        let array = result.as_array().unwrap();

        assert_eq!(array.len(), 1);
        let first = array[0].as_object().unwrap();
        assert_eq!(first.get("type").unwrap().as_bytes().unwrap(), b"domain");
        assert_eq!(first.get("value").unwrap().as_bytes().unwrap(), b"evil.com");
    }
}
