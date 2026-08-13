use std::{fs::File, io::BufReader};

use serde_json::{Value, from_reader, from_value};

use crate::{
    error::Error,
    manifest::{
        SuitCommand, SuitCommandEnum, SuitCommandSequence, SuitCommandSequenceEnum, SuitCommon,
        SuitManifest, SuitParameter,
    },
};

fn parse_suit_parameters(parse_key: &str, parse_value: &Value) -> Option<SuitParameter> {
    match parse_key {
        "vendor-id" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitVendorID(parse_value.to_string()),
        }),
        "class-id" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitClassID(parse_value.to_string()),
        }),
        "image-digest" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitImageDigest({
                let algorithm = match parse_value.get("algorithm") {
                    Some(str) => String::try_from(str.as_str().unwrap())
                        .map_err(|_| Error::UnsupportedParameter("Invalid algorithm".to_string()))
                        .unwrap(),
                    None => return None,
                };

                let digest = match parse_value.get("digest") {
                    Some(str) => String::try_from(str.as_str().unwrap())
                        .map_err(|_| Error::UnsupportedParameter("Invalid digest".to_string()))
                        .unwrap(),
                    None => return None,
                };

                crate::manifest::SuitDigest {
                    algorithm: algorithm,
                    digest: digest,
                }
            }),
        }),
        "component-slot" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitComponentSlot(parse_value.to_string()),
        }),
        "strict-order" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitStrictOrder(parse_value.to_string()),
        }),
        "soft-failure" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitSoftFailure(parse_value.to_string()),
        }),
        "image-size" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitImageSize(parse_value.to_string()),
        }),
        "content" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitContent(parse_value.to_string()),
        }),
        "uri" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitURI(parse_value.to_string()),
        }),
        "source-component" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitSourceComponent(
                parse_value.to_string(),
            ),
        }),
        "invoke-args" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitInvokeArgs(parse_value.to_string()),
        }),
        "device-id" => Some(SuitParameter {
            ident: crate::manifest::SuitParametersEnum::SuitDeviceID(parse_value.to_string()),
        }),
        _ => None,
    }
}

fn parse_suit_command(parse_key: &str, parse_value: &Value) -> Option<SuitCommand> {
    match parse_key {
        "suit-condition-vendor-identifier" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionVendorIdentifier,
            value: parse_value.to_string(),
        }),
        "suit-condition-class-identifier" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionClassIdentifier,
            value: parse_value.to_string(),
        }),
        "suit-condition-device-identifier" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionDeviceIdentifier,
            value: parse_value.to_string(),
        }),
        "suit-condition-image-match" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionImageMatch,
            value: parse_value.to_string(),
        }),
        "suit-condition-check-content" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionCheckContent,
            value: parse_value.to_string(),
        }),
        "suit-condition-component-slot" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionComponentSlot,
            value: parse_value.to_string(),
        }),
        "suit-condition-abort" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitConditionAbort,
            value: parse_value.to_string(),
        }),
        "suit-directive-set-component-index" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveSetComponentIndex,
            value: parse_value.to_string(),
        }),
        "suit-directive-try-each" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveTryEach,
            value: parse_value.to_string(),
        }),
        "suit-directive-override-parameters" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveOverrideParameters({
                let mut buf = Vec::new();
                for (key, value) in parse_value
                    .as_object()
                    .ok_or_else(|| "No valid suit parameter".to_string())
                    .unwrap()
                {
                    buf.push(
                        parse_suit_parameters(key, value)
                            .ok_or_else(|| "Invalid parameter".to_string())
                            .unwrap(),
                    )
                }
                buf
            }),
            value: parse_value.to_string(),
        }),
        "suit-directive-fetch" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveFetch,
            value: parse_value.to_string(),
        }),
        "suit-directive-copy" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveCopy,
            value: parse_value.to_string(),
        }),
        "suit-directive-write" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveWrite,
            value: parse_value.to_string(),
        }),
        "suit-directive-invoke" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveInvoke,
            value: parse_value.to_string(),
        }),
        "suit-directive-run-sequence" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveRunSequence,
            value: parse_value.to_string(),
        }),
        "suit-directive-swap" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitDirectiveSwap,
            value: parse_value.to_string(),
        }),
        "suit-command-custom" => Some(SuitCommand {
            ident: SuitCommandEnum::SuitCommandCustom,
            value: parse_value.to_string(),
        }),
        _ => None,
    }
}

// Parse suit command sequence (not shared), later distinction between severable and unseverable possible, maybe only relevant for encoding module
fn parse_suit_command_sequence(
    parse_key: &str,
    parse_value: &Value,
) -> Option<SuitCommandSequence> {
    match parse_key {
        "payload-fetch" => {
            let suit_commands = parse_suit_command_sequence_identifier(parse_value);
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitPayloadFetch,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "payload-installation" => {
            let suit_commands = parse_suit_command_sequence_identifier(parse_value);
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitInstall,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "image-validation" => {
            let suit_commands = parse_suit_command_sequence_identifier(parse_value);
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitValidate,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "suit-load" => {
            let suit_commands = parse_suit_command_sequence_identifier(parse_value);
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitLoad,
                actions: suit_commands,
            };
            Some(command_seq)
        }
        "suit-invoke" => {
            let suit_commands = parse_suit_command_sequence_identifier(parse_value);
            let command_seq = SuitCommandSequence {
                sequence: SuitCommandSequenceEnum::SuitInvoke,
                actions: suit_commands,
            };
            Some(command_seq)
        }

        _ => None,
    }
}

fn parse_suit_command_sequence_identifier(parse_value: &Value) -> Vec<SuitCommand> {
    let mut seq_buf = Vec::new();
    for (key, value) in parse_value
        .as_object()
        .ok_or_else(|| "No shared sequence. Suit manifest needs a shared sequence".to_string())
        .unwrap()
    {
        seq_buf.push(
            parse_suit_command(&key.to_string(), value)
                .ok_or_else(|| Error::UnsupportedCommand("Invalid shared sequence command".to_string()))
                .unwrap(),
        );
    }
    return seq_buf;
}

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
        .ok_or_else(|| "No command sequence. Suit manifest needs a command sequence")
        .unwrap();

    let components_value = suit_common
        .get("suit-components")
        .ok_or_else(|| "No components. Suit manifest need at least one component".to_string())
        .unwrap();

    // Directly deserialize the nested structure
    let components: Vec<Vec<String>> = from_value(components_value.clone()).unwrap();

    // Parse shared sequence

    let mut shared_seq_buf = Vec::new();

    for (key, value) in suit_common["suit-shared-sequence"]
        .as_object()
        .ok_or_else(|| "No shared sequence. Suit manifest needs a shared sequence".to_string())
        .unwrap()
    {
        // Shared sequence has commands directly
        shared_seq_buf.push(
            parse_suit_command(&key.to_string(), value)
                .ok_or_else(|| Error::UnsupportedCommand("Invalid shared sequence command".to_string()))
                .unwrap(),
        );
    }
    
    // Create suit common out of components & shared_sequence

    let suit_common = SuitCommon {
        components: components,
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
        version: version,
        sequence_number: sequence_number,
        suit_common: suit_common,
        sequence: seq_buf,
    })
}
