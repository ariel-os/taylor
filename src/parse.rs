//! Parses a JSON manifest description into a [`crate::manifest::SuitManifest`]. The expected
//! shape is described in the
//! [repo README](https://github.com/ariel-os/taylor#supported-manifest-members).

use std::io::Read;

use serde_bytes::ByteBuf;
use serde_json::{Value, from_reader};

use crate::{
    error::Error,
    manifest::{
        SuitCommand, SuitCommandEnum, SuitCommandSequence, SuitCommandSequenceEnum, SuitCommon,
        SuitManifest, SuitParameter,
    },
};

/// Strips dashes and hex-decodes a UUID string into its raw 16 bytes.
fn parse_uuid_bytes(s: &str) -> Result<Vec<u8>, Error> {
    let stripped: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(stripped)
        .map_err(|_| Error::UnsupportedParameter("Invalid UUID hex".to_string()))?;
    if bytes.len() != 16 {
        return Err(Error::UnsupportedParameter(
            "UUID must be 16 bytes".to_string(),
        ));
    }
    Ok(bytes)
}

/// Maps the JSON comparison names to `SUIT_Condition_Version_Comparison_Types`.
fn parse_version_comparison(s: &str) -> Option<crate::manifest::VersionComparisonType> {
    use crate::manifest::VersionComparisonType::*;
    match s {
        "greater" => Some(Greater),
        "greater-equal" => Some(GreaterOrEqual),
        "equal" => Some(Equal),
        "lesser-equal" => Some(LesserOrEqual),
        "lesser" => Some(Lesser),
        _ => None,
    }
}

fn parse_suit_parameters(parse_key: &str, parse_value: &Value) -> Result<SuitParameter, Error> {
    use crate::manifest::SuitParametersEnum as Param;

    let invalid = || Error::UnsupportedParameter(format!("Invalid {parse_key} parameter"));
    let as_str = || parse_value.as_str().ok_or_else(invalid);
    let as_u64 = || parse_value.as_u64().ok_or_else(invalid);
    let as_bool = || parse_value.as_bool().ok_or_else(invalid);
    let as_uuid = |s: &str| parse_uuid_bytes(s).map_err(|_| invalid());
    let as_hex = |s: &str| hex::decode(s).map_err(|_| invalid());

    let ident = match parse_key {
        "vendor-id" => Param::SuitVendorID(as_uuid(as_str()?)?),
        "class-id" => Param::SuitClassID(as_uuid(as_str()?)?),
        "image-digest" => {
            let algorithm = parse_value.get("algorithm").and_then(Value::as_str);
            let algorithm = algorithm.ok_or_else(invalid)?;
            if crate::encode::digest_algorithm_id(algorithm).is_none() {
                let message = format!("{algorithm} for {parse_key}");
                return Err(Error::UnsupportedAlgorithm(message));
            }
            let algorithm = algorithm.to_string();
            let digest = parse_value.get("digest").and_then(Value::as_str);
            let digest = as_hex(digest.ok_or_else(invalid)?)?;
            Param::SuitImageDigest(crate::manifest::SuitDigest { algorithm, digest })
        }
        "component-slot" => Param::SuitComponentSlot(as_u64()?),
        "strict-order" => Param::SuitStrictOrder(as_bool()?),
        "soft-failure" => Param::SuitSoftFailure(as_bool()?),
        "image-size" => Param::SuitImageSize(as_u64()?),
        "content" => Param::SuitContent(as_hex(as_str()?)?),
        "uri" => Param::SuitURI(as_str()?.to_string()),
        "source-component" => Param::SuitSourceComponent(as_u64()?),
        "invoke-args" => Param::SuitInvokeArgs(as_hex(as_str()?)?),
        "device-id" => Param::SuitDeviceID(as_uuid(as_str()?)?),
        "fetch-arguments" => Param::SuitFetchArguments(as_hex(as_str()?)?),
        "version" => Param::SuitVersion(parse_version_match(parse_value).ok_or_else(invalid)?),
        _ => {
            let message = format!("Unknown parameter {parse_key}");
            return Err(Error::UnsupportedParameter(message));
        }
    };
    Ok(SuitParameter { ident })
}

/// Reads a `{"comparison": ..., "value": [...]}` object as a `SUIT_Parameter_Version_Match`.
fn parse_version_match(value: &Value) -> Option<crate::manifest::SuitVersionMatch> {
    Some(crate::manifest::SuitVersionMatch {
        comparison: parse_version_comparison(value.get("comparison")?.as_str()?)?,
        value: value
            .get("value")?
            .as_array()?
            .iter()
            .map(Value::as_i64)
            .collect::<Option<Vec<i64>>>()?,
    })
}

fn parse_suit_command(parse_key: &str, parse_value: &Value) -> Result<SuitCommand, Error> {
    let invalid = |what: &str| Error::UnsupportedCommand(format!("Invalid {} argument", what));

    let ident = match parse_key {
        "suit-condition-vendor-identifier" => SuitCommandEnum::SuitConditionVendorIdentifier(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-class-identifier" => SuitCommandEnum::SuitConditionClassIdentifier(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-device-identifier" => SuitCommandEnum::SuitConditionDeviceIdentifier(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-image-match" => SuitCommandEnum::SuitConditionImageMatch(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-check-content" => SuitCommandEnum::SuitConditionCheckContent(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-component-slot" => SuitCommandEnum::SuitConditionComponentSlot(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-abort" => SuitCommandEnum::SuitConditionAbort(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-directive-set-component-index" => SuitCommandEnum::SuitDirectiveSetComponentIndex(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-directive-try-each" => {
            let branches_value = parse_value.as_array().ok_or_else(|| invalid(parse_key))?;

            let mut else_nil = false;
            let mut branches = Vec::new();
            for branch_value in branches_value {
                if branch_value.is_null() {
                    else_nil = true;
                    continue;
                }
                branches.push(parse_command_sequence(branch_value)?);
            }
            SuitCommandEnum::SuitDirectiveTryEach(branches, else_nil)
        }
        "suit-directive-override-parameters" => {
            let mut buf = Vec::new();
            for (key, value) in parse_value.as_object().ok_or_else(|| invalid(parse_key))? {
                buf.push(parse_suit_parameters(key, value)?);
            }
            SuitCommandEnum::SuitDirectiveOverrideParameters(buf)
        }
        "suit-directive-fetch" => SuitCommandEnum::SuitDirectiveFetch(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-directive-copy" => SuitCommandEnum::SuitDirectiveCopy(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-directive-write" => SuitCommandEnum::SuitDirectiveWrite(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-directive-invoke" => SuitCommandEnum::SuitDirectiveInvoke(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-directive-run-sequence" => {
            SuitCommandEnum::SuitDirectiveRunSequence(parse_command_sequence(parse_value)?)
        }
        "suit-directive-swap" => SuitCommandEnum::SuitDirectiveSwap(
            parse_value.as_u64().ok_or_else(|| invalid(parse_key))?,
        ),
        "suit-condition-version" => match parse_value.as_u64() {
            // Raw form: a plain SUIT_Rep_Policy bitmask, paired with a "version"
            // parameter set separately via suit-directive-override-parameters.
            Some(policy) => SuitCommandEnum::SuitConditionVersion(policy),
            // Convenience form: {"comparison": "...", "value": [[..], [..], ...]}.
            // suit-condition-version/suit-parameter-version only compare against one
            // version at a time, so a list of acceptable versions has no direct CDDL
            // encoding; this expands to one override-parameters+condition pair per
            // version, OR-combined via suit-directive-try-each (spec-conformant CBOR).
            None => {
                let obj = parse_value.as_object().ok_or_else(|| invalid(parse_key))?;
                let comparison = parse_version_comparison(
                    obj.get("comparison")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid(parse_key))?,
                )
                .ok_or_else(|| invalid(parse_key))?;
                let policy = match obj.get("policy") {
                    None => 15,
                    Some(policy) => policy.as_u64().ok_or_else(|| invalid(parse_key))?,
                };
                let versions = obj
                    .get("value")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid(parse_key))?;

                let mut branches = Vec::new();
                for version in versions {
                    let value = version
                        .as_array()
                        .ok_or_else(|| invalid(parse_key))?
                        .iter()
                        .map(Value::as_i64)
                        .collect::<Option<Vec<i64>>>()
                        .ok_or_else(|| invalid(parse_key))?;
                    branches.push(vec![
                        SuitCommand {
                            ident: SuitCommandEnum::SuitDirectiveOverrideParameters(vec![
                                SuitParameter {
                                    ident: crate::manifest::SuitParametersEnum::SuitVersion(
                                        crate::manifest::SuitVersionMatch { comparison, value },
                                    ),
                                },
                            ]),
                        },
                        SuitCommand {
                            ident: SuitCommandEnum::SuitConditionVersion(policy),
                        },
                    ]);
                }
                SuitCommandEnum::SuitDirectiveTryEach(branches, false)
            }
        },
        "suit-command-custom" => SuitCommandEnum::SuitCommandCustom(parse_value.to_string()),
        _ => {
            return Err(Error::UnsupportedCommand(format!(
                "Unknown command {}",
                parse_key
            )));
        }
    };

    Ok(SuitCommand { ident })
}

/// Parses a command sequence encoded as a JSON array of single-key command objects,
/// e.g. `[{"suit-directive-set-component-index": 0}, {"suit-directive-fetch": 2}]`.
fn parse_command_sequence(parse_value: &Value) -> Result<Vec<SuitCommand>, Error> {
    let commands = parse_value
        .as_array()
        .ok_or_else(|| Error::UnsupportedCommand("Invalid command sequence".to_string()))?;

    let mut buf = Vec::new();
    for command in commands {
        let obj = command
            .as_object()
            .ok_or_else(|| Error::UnsupportedCommand("Invalid command entry".to_string()))?;
        let mut entries = obj.iter();
        let (Some((key, value)), None) = (entries.next(), entries.next()) else {
            let message = format!("Command entry must have exactly one key, got {}", obj.len());
            return Err(Error::UnsupportedCommand(message));
        };
        buf.push(parse_suit_command(key, value)?);
    }
    Ok(buf)
}

// Parse suit command sequence (not shared), later distinction between severable and unseverable possible, maybe only relevant for encoding module
//
// NOTE: the accepted top-level `sequence` object keys are `payload-fetch`,
// `payload-installation`, `image-validation`, `suit-load`, `suit-invoke` - not the CDDL
// phase names (`suit-payload-fetch`, `suit-install`, `suit-validate`). Any other key is
// rejected with `Error::UnsupportedCommand`.
fn parse_suit_command_sequence(
    parse_key: &str,
    parse_value: &Value,
) -> Result<SuitCommandSequence, Error> {
    let sequence = match parse_key {
        "payload-fetch" => SuitCommandSequenceEnum::SuitPayloadFetch,
        "payload-installation" => SuitCommandSequenceEnum::SuitInstall,
        "image-validation" => SuitCommandSequenceEnum::SuitValidate,
        "suit-load" => SuitCommandSequenceEnum::SuitLoad,
        "suit-invoke" => SuitCommandSequenceEnum::SuitInvoke,
        _ => {
            let message = format!("Unknown command sequence {parse_key}");
            return Err(Error::UnsupportedCommand(message));
        }
    };
    let actions = parse_command_sequence(parse_value).map_err(|e| e.in_location(parse_key))?;
    Ok(SuitCommandSequence { sequence, actions })
}

/// Reads the required top-level member `key` as a non-negative integer.
fn parse_usize_member(data: &Value, key: &str) -> Result<usize, Error> {
    data.get(key)
        .ok_or_else(|| Error::UnsupportedInput(format!("No {key}")))?
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| Error::UnsupportedInput(format!("Invalid {key}")))
}

/// Reads a JSON manifest description from `reader` and builds a [`SuitManifest`].
///
/// # Errors
///
/// Returns [`Error::InvalidJson`] if `reader` doesn't contain valid JSON, and another
/// [`Error`] variant if a required member is missing or any member, command, or parameter is
/// malformed or unsupported.
///
/// # Examples
///
/// ```
/// use std::fs::{self, File};
/// use std::io::BufReader;
/// use taylor::parse::parse;
///
/// let path = std::env::temp_dir().join("taylor_parse_doctest.json");
/// fs::write(&path, r#"{
///     "version": 1,
///     "sequence-number": 1,
///     "suit-common": {
///         "suit-components": [["00"]],
///         "suit-shared-sequence": []
///     },
///     "sequence": {}
/// }"#).unwrap();
///
/// let mut reader = BufReader::new(File::open(&path).unwrap());
/// let manifest = parse(&mut reader).unwrap();
/// assert_eq!(manifest.version, 1);
/// assert_eq!(manifest.sequence_number, 1);
/// assert!(manifest.sequence.is_empty());
///
/// fs::remove_file(&path).unwrap();
/// ```
pub fn parse<R: Read>(reader: &mut R) -> Result<SuitManifest, Error> {
    let data: Value = from_reader(reader).map_err(Error::InvalidJson)?;

    let version = parse_usize_member(&data, "version")?;

    let suit_set_version = data
        .get("suit-set-version")
        .map(|value| {
            let values = value
                .as_array()
                .filter(|values| !values.is_empty())
                .ok_or_else(|| Error::UnsupportedInput("Invalid suit-set-version".to_string()))?;
            values
                .iter()
                .map(Value::as_i64)
                .collect::<Option<Vec<i64>>>()
                .ok_or_else(|| Error::UnsupportedInput("Invalid suit-set-version".to_string()))
        })
        .transpose()?;

    let sequence_number = parse_usize_member(&data, "sequence-number")?;

    let suit_common = data
        .get("suit-common")
        .ok_or_else(|| Error::UnsupportedInput("No suit-common".to_string()))?;

    let components_value = suit_common
        .get("suit-components")
        .ok_or_else(|| Error::UnsupportedInput("No suit-components".to_string()))?;

    // Component identifiers are hex-encoded bstr segments, decoded generically (no special
    // per-label knowledge needed).
    let invalid_components = || Error::UnsupportedInput("Invalid suit-components".to_string());
    let components = components_value
        .as_array()
        .ok_or_else(invalid_components)?
        .iter()
        .map(|segments| {
            segments
                .as_array()
                .ok_or_else(invalid_components)?
                .iter()
                .map(|segment| {
                    let hex_segment = segment.as_str().ok_or_else(invalid_components)?;
                    hex::decode(hex_segment)
                        .map(ByteBuf::from)
                        .map_err(|_| invalid_components())
                })
                .collect::<Result<Vec<ByteBuf>, Error>>()
        })
        .collect::<Result<Vec<Vec<ByteBuf>>, Error>>()?;

    // Parse shared sequence

    let shared_seq_buf = parse_command_sequence(&suit_common["suit-shared-sequence"])
        .map_err(|e| e.in_location("suit-shared-sequence"))?;

    // Create suit common out of components & shared_sequence

    let suit_common = SuitCommon {
        components,
        shared_sequence: shared_seq_buf,
    };

    // Parse command sequence

    // All phase sequences are individually optional per CDDL (SUIT_Unseverable_Members /
    // SUIT_Severable_Members_Choice are all `?`); an absent "sequence" key means none are set.
    let mut seq_buf = Vec::new();

    if let Some(seq_value) = data.get("sequence") {
        let phases = seq_value
            .as_object()
            .ok_or_else(|| Error::UnsupportedCommand("Invalid command sequence".to_string()))?;
        for (key, value) in phases {
            seq_buf.push(parse_suit_command_sequence(key, value)?);
        }
    }

    Ok(SuitManifest {
        version,
        suit_set_version,
        sequence_number,
        suit_common,
        sequence: seq_buf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{SuitCommandEnum, SuitParametersEnum, VersionComparisonType};
    use serde_json::json;

    #[test]
    fn parse_uuid_bytes_accepts_dashed_uuid() {
        let bytes = parse_uuid_bytes("5a615b0b-cdf3-5c19-9d90-d3b2a54c9f18").unwrap();
        assert_eq!(
            bytes,
            hex::decode("5a615b0bcdf35c199d90d3b2a54c9f18").unwrap()
        );
    }

    #[test]
    fn parse_uuid_bytes_rejects_wrong_length() {
        assert!(parse_uuid_bytes("00112233").is_err());
    }

    #[test]
    fn parse_version_comparison_maps_all_known_names() {
        assert!(matches!(
            parse_version_comparison("greater"),
            Some(VersionComparisonType::Greater)
        ));
        assert!(matches!(
            parse_version_comparison("equal"),
            Some(VersionComparisonType::Equal)
        ));
        assert!(parse_version_comparison("not-a-comparison").is_none());
    }

    #[test]
    fn suit_condition_version_raw_form_is_a_plain_policy() {
        let cmd = parse_suit_command("suit-condition-version", &json!(15)).unwrap();
        assert!(matches!(
            cmd.ident,
            SuitCommandEnum::SuitConditionVersion(15)
        ));
    }

    /// The `{"comparison", "value": [[..], ...]}` shorthand must expand to exactly one
    /// `[override-parameters{version}, suit-condition-version(policy)]` branch per listed
    /// version, OR-combined via `suit-directive-try-each` — never a partial/reordered set.
    #[test]
    fn suit_condition_version_shorthand_expands_to_one_try_each_branch_per_version() {
        let cmd = parse_suit_command(
            "suit-condition-version",
            &json!({"comparison": "equal", "value": [[1, 0, 0], [1, 1, 0], [2, 0, 0]]}),
        )
        .unwrap();

        let SuitCommandEnum::SuitDirectiveTryEach(branches, else_nil) = cmd.ident else {
            panic!("expected SuitDirectiveTryEach, got {:?}", cmd.ident);
        };
        assert!(!else_nil, "shorthand must not add a nil fallback branch");
        assert_eq!(branches.len(), 3);

        let expected_versions = [vec![1, 0, 0], vec![1, 1, 0], vec![2, 0, 0]];
        for (branch, expected_value) in branches.iter().zip(expected_versions) {
            assert_eq!(
                branch.len(),
                2,
                "each branch must set the parameter then check it"
            );

            let SuitCommandEnum::SuitDirectiveOverrideParameters(params) = &branch[0].ident else {
                panic!(
                    "branch[0] must be override-parameters, got {:?}",
                    branch[0].ident
                );
            };
            assert_eq!(params.len(), 1);
            let SuitParametersEnum::SuitVersion(version_match) = &params[0].ident else {
                panic!("expected a version parameter, got {:?}", params[0].ident);
            };
            assert!(matches!(
                version_match.comparison,
                VersionComparisonType::Equal
            ));
            assert_eq!(version_match.value, expected_value);

            assert!(matches!(
                branch[1].ident,
                SuitCommandEnum::SuitConditionVersion(15)
            ));
        }
    }

    #[test]
    fn suit_condition_version_shorthand_honours_explicit_policy() {
        let cmd = parse_suit_command(
            "suit-condition-version",
            &json!({"comparison": "greater-equal", "value": [[1, 0, 0]], "policy": 3}),
        )
        .unwrap();
        let SuitCommandEnum::SuitDirectiveTryEach(branches, _) = cmd.ident else {
            panic!("expected SuitDirectiveTryEach");
        };
        assert!(matches!(
            branches[0][1].ident,
            SuitCommandEnum::SuitConditionVersion(3)
        ));
    }

    #[test]
    fn unknown_command_key_is_an_error() {
        let err = parse_suit_command("suit-directive-nonexistent", &json!(1)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCommand(_)));
    }

    #[test]
    fn vendor_and_class_id_parameters_hex_decode_to_sixteen_bytes() {
        let vendor =
            parse_suit_parameters("vendor-id", &json!("5a615b0b-cdf3-5c19-9d90-d3b2a54c9f18"))
                .unwrap();
        let SuitParametersEnum::SuitVendorID(bytes) = vendor.ident else {
            panic!("expected SuitVendorID");
        };
        assert_eq!(bytes.len(), 16);
    }

    fn parse_str(json: &str) -> Result<SuitManifest, Error> {
        parse(&mut json.as_bytes())
    }

    fn manifest_with(common: Value) -> String {
        json!({"version": 1, "sequence-number": 1, "suit-common": common}).to_string()
    }

    fn manifest_with_shared(command: Value) -> String {
        manifest_with(json!({
            "suit-components": [["00"]],
            "suit-shared-sequence": [command],
        }))
    }

    #[test]
    fn malformed_top_level_input_is_an_error_not_a_panic() {
        let cases = [
            ("not json", "{"),
            ("missing version", r#"{"sequence-number": 1}"#),
            ("string version", r#"{"version": "1"}"#),
            ("missing sequence-number", r#"{"version": 1}"#),
            (
                "negative sequence-number",
                r#"{"version": 1, "sequence-number": -1}"#,
            ),
            (
                "missing suit-common",
                r#"{"version": 1, "sequence-number": 1}"#,
            ),
        ];
        for (name, json) in cases {
            assert!(parse_str(json).is_err(), "{name} must be rejected");
        }
        assert!(matches!(parse_str("{"), Err(Error::InvalidJson(_))));
    }

    #[test]
    fn malformed_components_are_an_error_not_a_panic() {
        let cases = [
            (
                "missing suit-components",
                json!({"suit-shared-sequence": []}),
            ),
            ("components not an array", json!({"suit-components": "00"})),
            (
                "identifier not an array",
                json!({"suit-components": ["00"]}),
            ),
            ("segment not a string", json!({"suit-components": [[0]]})),
            ("segment not hex", json!({"suit-components": [["zz"]]})),
        ];
        for (name, common) in cases {
            assert!(
                parse_str(&manifest_with(common)).is_err(),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn malformed_sequence_object_is_an_error_not_a_panic() {
        let json = json!({
            "version": 1,
            "sequence-number": 1,
            "suit-common": {"suit-components": [["00"]], "suit-shared-sequence": []},
            "sequence": [],
        });
        assert!(parse_str(&json.to_string()).is_err());
    }

    #[test]
    fn malformed_image_digest_is_an_error_not_a_panic() {
        let cases = [
            (
                "algorithm not a string",
                json!({"algorithm": 1, "digest": "00"}),
            ),
            (
                "unknown algorithm",
                json!({"algorithm": "md5", "digest": "00"}),
            ),
            (
                "digest not a string",
                json!({"algorithm": "sha256", "digest": 0}),
            ),
            (
                "digest not hex",
                json!({"algorithm": "sha256", "digest": "zz"}),
            ),
        ];
        for (name, digest) in cases {
            let command = json!({"suit-directive-override-parameters": {"image-digest": digest}});
            assert!(
                parse_str(&manifest_with_shared(command)).is_err(),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn supported_digest_algorithms_still_parse() {
        for algorithm in ["sha256", "sha384", "sha512"] {
            let command = json!({"suit-directive-override-parameters": {
                "image-digest": {"algorithm": algorithm, "digest": "00"}
            }});
            assert!(
                parse_str(&manifest_with_shared(command)).is_ok(),
                "{algorithm} must be accepted"
            );
        }
    }

    fn manifest_with_sequence(sequence: Value) -> String {
        json!({
            "version": 1,
            "sequence-number": 1,
            "suit-common": {"suit-components": [["00"]], "suit-shared-sequence": []},
            "sequence": sequence,
        })
        .to_string()
    }

    #[test]
    fn unsupported_digest_algorithm_error_names_algorithm_and_location() {
        let command = json!({"suit-directive-override-parameters": {
            "image-digest": {"algorithm": "md5", "digest": "00"}
        }});
        let err = parse_str(&manifest_with_shared(command)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedAlgorithm(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("md5"), "{message}");
        assert!(message.contains("suit-shared-sequence"), "{message}");
    }

    #[test]
    fn bad_vendor_id_error_names_parameter_and_location() {
        let command = json!({"suit-directive-override-parameters": {"vendor-id": "00"}});
        let message = parse_str(&manifest_with_shared(command))
            .unwrap_err()
            .to_string();
        assert!(message.contains("vendor-id"), "{message}");
        assert!(message.contains("suit-shared-sequence"), "{message}");
    }

    #[test]
    fn unknown_parameter_error_says_so() {
        let command = json!({"suit-directive-override-parameters": {"no-such-param": 1}});
        let err = parse_str(&manifest_with_shared(command)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedParameter(_)), "{err:?}");
        assert!(err.to_string().contains("Unknown parameter"), "{err}");
    }

    #[test]
    fn invalid_command_argument_error_names_its_phase() {
        let sequence = json!({"payload-installation": [{"suit-directive-fetch": "two"}]});
        let err = parse_str(&manifest_with_sequence(sequence)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCommand(_)), "{err:?}");
        assert!(
            err.to_string().ends_with("in payload-installation"),
            "{err}"
        );
    }

    #[test]
    fn unknown_phase_error_says_so() {
        let sequence = json!({"no-such-phase": []});
        let err = parse_str(&manifest_with_sequence(sequence)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCommand(_)), "{err:?}");
        assert!(
            err.to_string().contains("Unknown command sequence"),
            "{err}"
        );
    }

    #[test]
    fn error_inside_nested_try_each_keeps_shared_sequence_location() {
        let command = json!({"suit-directive-try-each": [[{"suit-directive-fetch": "two"}]]});
        let err = parse_str(&manifest_with_shared(command)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCommand(_)), "{err:?}");
        assert!(err.to_string().contains("in suit-shared-sequence"), "{err}");
    }

    #[test]
    fn command_entry_with_more_than_one_key_is_rejected() {
        let sequence = json!([{"suit-directive-fetch": 2, "suit-directive-invoke": 2}]);
        let err = parse_command_sequence(&sequence).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCommand(_)), "{err:?}");
        assert!(err.to_string().contains("exactly one key, got 2"), "{err}");
    }

    #[test]
    fn empty_command_entry_is_rejected() {
        let err = parse_command_sequence(&json!([{}])).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCommand(_)), "{err:?}");
    }

    #[test]
    fn suit_condition_version_shorthand_rejects_non_u64_policy() {
        for policy in [json!("3"), json!(-1)] {
            let value = json!({"comparison": "equal", "value": [[1, 0, 0]], "policy": policy});
            let err = parse_suit_command("suit-condition-version", &value).unwrap_err();
            assert!(
                matches!(err, Error::UnsupportedCommand(_)),
                "policy {policy} must be rejected, got {err:?}"
            );
        }
    }
}
