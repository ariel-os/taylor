//! Parses a JSON manifest description (see [the repo README](https://github.com/schnitzm/taylor#usage)
//! for the expected shape) into a [`crate::manifest::SuitManifest`].

use std::{fs::File, io::BufReader};

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
        return Err(Error::UnsupportedParameter("UUID must be 16 bytes".to_string()));
    }
    Ok(bytes)
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
            ident: crate::manifest::SuitParametersEnum::SuitSourceComponent(
                parse_value.as_u64()?,
            ),
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
            let branches_value = parse_value
                .as_array()
                .ok_or_else(|| invalid(parse_key))?;

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
            for (key, value) in parse_value
                .as_object()
                .ok_or_else(|| invalid(parse_key))?
            {
                buf.push(
                    parse_suit_parameters(key, value)
                        .ok_or_else(|| Error::UnsupportedParameter("Invalid parameter".to_string()))?,
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
        "suit-command-custom" => SuitCommandEnum::SuitCommandCustom(parse_value.to_string()),
        _ => return Err(Error::UnsupportedCommand(format!("Unknown command {}", parse_key))),
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
        .ok_or("No command sequence. Suit manifest needs a command sequence")
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
                        hex::decode(segment.as_str().expect("component segment must be a string"))
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

    let seq_value = data
        .get("sequence")
        .ok_or_else(|| "No command sequence. Suit manifest needs a command sequence".to_string())
        .unwrap();

    let mut seq_buf = Vec::new();

    for (key, value) in seq_value
        .as_object()
        .ok_or_else(|| "No valid command sequence".to_string())
        .unwrap()
    {
        seq_buf.push(
            parse_suit_command_sequence(key, value)
                .ok_or_else(|| Error::UnsupportedCommand("Invalid command sequence member".to_string()))
                .unwrap(),
        );
    }

    Ok(SuitManifest {
        version,
        sequence_number,
        suit_common,
        sequence: seq_buf,
    })
}
