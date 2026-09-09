//! Parses a JSON manifest description (see [the repo README](https://github.com/schnitzm/taylor#usage)
//! for the expected shape) into a [`crate::manifest::SuitManifest`].

use std::{fs::File, io::BufReader};

use serde_bytes::ByteBuf;
use serde_json::{from_reader, Value};

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

fn parse_suit_parameters(parse_key: &str, parse_value: &Value) -> Option<SuitParameter> {
    match parse_key {
        "vendor-id" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitVendorID(
                parse_uuid_bytes(parse_value.as_str()?).ok()?,
            ),
        }),
        "class-id" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitClassID(
                parse_uuid_bytes(parse_value.as_str()?).ok()?,
            ),
        }),
        "image-digest" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitImageDigest({
                let algorithm = {
                    let algo = parse_value.get("algorithm")?;
                    algo.as_str().unwrap().to_string()
                };

                let digest = {
                    let str = parse_value.get("digest")?;
                    hex::decode(str.as_str().unwrap())
                .map_err(|_| Error::UnsupportedParameter("Invalid digest hex".to_string()))
                .unwrap()
                };

                crate::manifest::SuitDigest {
                    algorithm,
                    digest,
                }
            }),
        }),
        "component-slot" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitComponentSlot(parse_value.as_u64()?),
        }),
        "strict-order" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitStrictOrder(parse_value.as_bool()?),
        }),
        "soft-failure" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitSoftFailure(parse_value.as_bool()?),
        }),
        "image-size" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitImageSize(parse_value.as_u64()?),
        }),
        "content" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitContent(
                hex::decode(parse_value.as_str()?).ok()?,
            ),
        }),
        "uri" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitURI(parse_value.as_str()?.to_string()),
        }),
        "source-component" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitSourceComponent(parse_value.as_u64()?),
        }),
        "invoke-args" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitInvokeArgs(
                hex::decode(parse_value.as_str()?).ok()?,
            ),
        }),
        "device-id" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitDeviceID(
                parse_uuid_bytes(parse_value.as_str()?).ok()?,
            ),
        }),
        "fetch-arguments" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitFetchArguments(
                hex::decode(parse_value.as_str()?).ok()?,
            ),
        }),
        "version" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitVersion(
                crate::manifest::SuitVersionMatch {
                    comparison: parse_version_comparison(parse_value.get("comparison")?.as_str()?)?,
                    value: parse_value
                        .get("value")?
                        .as_array()?
                        .iter()
                        .map(|v| v.as_i64())
                        .collect::<Option<Vec<i64>>>()?,
                },
            ),
        }),
        _ => None,
    }
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
                buf.push(
                    parse_suit_parameters(key, value).ok_or_else(|| {
                        Error::UnsupportedParameter("Invalid parameter".to_string())
                    })?,
                )
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
                let policy = obj.get("policy").and_then(Value::as_u64).unwrap_or(15);
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
            )))
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
        let (key, value) = obj
            .iter()
            .next()
            .ok_or_else(|| Error::UnsupportedCommand("Empty command entry".to_string()))?;
        buf.push(parse_suit_command(key, value)?);
    }
    Ok(buf)
}

// Parse suit command sequence (not shared), later distinction between severable and unseverable possible, maybe only relevant for encoding module
fn parse_suit_command_sequence(
    parse_key: &str,
    parse_value: &Value,
) -> Option<SuitCommandSequence> {
    match parse_key {
        "payload-fetch" => {
            let suit_commands = parse_command_sequence(parse_value).ok()?;
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitPayloadFetch,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "payload-installation" => {
            let suit_commands = parse_command_sequence(parse_value).ok()?;
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitInstall,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "image-validation" => {
            let suit_commands = parse_command_sequence(parse_value).ok()?;
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitValidate,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "suit-load" => {
            let suit_commands = parse_command_sequence(parse_value).ok()?;
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitLoad,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "suit-invoke" => {
            let suit_commands = parse_command_sequence(parse_value).ok()?;
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitInvoke,
                actions: suit_commands,
            };
            Some(command_seq)
        }

        _ => None,
    }
}

/// Reads a JSON manifest description from `reader` and builds a [`SuitManifest`].
///
/// # Panics
///
/// Panics (rather than returning `Err`) on several classes of malformed input; only a subset
/// of validation currently returns [`Error`]. Treat this as a CLI-oriented parser, not a
/// hardened one.
pub fn parse(reader: &mut BufReader<File>) -> Result<SuitManifest, Error> {
    let data: Value = from_reader(reader).expect("JSON-Daten konnten nicht verarbeitet werden");

    // Critical Metadata

    // Parse version

    let version = match data.get("version") {
        Some(num) => usize::try_from(num.as_u64().unwrap())
            .map_err(|_| Error::UnsupportedInput("Invalid version".to_string()))?,
        None => return Err(Error::UnsupportedInput("No version".to_string())),
    };

    // Parse sequence number

    let sequence_number = match data.get("sequence-number") {
        Some(num) => usize::try_from(num.as_u64().unwrap())
            .map_err(|_| Error::UnsupportedInput("Invalid sequence number".to_string()))?,
        None => return Err(Error::UnsupportedInput("No sequence number".to_string())),
    };

    // Parse suit common

    let suit_common = data
        .get("suit-common")
        .ok_or("No suit-common. Suit manifest needs a suit-common section")
        .unwrap();

    let components_value = suit_common
        .get("suit-components")
        .ok_or("No components. Suit manifest need at least one component")
        .unwrap();

    // Component identifiers are hex-encoded bstr segments, decoded generically (no special
    // per-label knowledge needed).
    let components: Vec<Vec<ByteBuf>> = components_value
        .as_array()
        .ok_or_else(|| "Invalid suit-components".to_string())
        .unwrap()
        .iter()
        .map(|segments| {
            segments
                .as_array()
                .ok_or_else(|| "Invalid component identifier".to_string())
                .unwrap()
                .iter()
                .map(|segment| {
                    ByteBuf::from(
                        hex::decode(
                            segment
                                .as_str()
                                .expect("component segment must be a string"),
                        )
                        .expect("component segment must be valid hex"),
                    )
                })
                .collect()
        })
        .collect();

    // Parse shared sequence

    let shared_seq_buf = parse_command_sequence(&suit_common["suit-shared-sequence"])
        .map_err(|_| Error::UnsupportedCommand("Invalid shared sequence".to_string()))?;

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
        for (key, value) in seq_value
            .as_object()
            .ok_or_else(|| "No valid command sequence".to_string())
            .unwrap()
        {
            let command_seq = parse_suit_command_sequence(key, value).ok_or_else(|| {
                Error::UnsupportedCommand("Invalid command sequence member".to_string())
            })?;
            seq_buf.push(command_seq);
        }
    }

    Ok(SuitManifest {
        version,
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
}
