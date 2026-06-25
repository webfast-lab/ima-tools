use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

impl std::str::FromStr for HashAlgorithm {
    type Err = ImaReplayError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            _ => Err(ImaReplayError::UnsupportedAlgorithm(value.to_owned())),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayOptions {
    pub algorithm: HashAlgorithm,
    pub pcr: u32,
    pub count: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MeasurementRecord {
    pcr: u32,
    template_digest: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ImaReplayError {
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("unable to recognize input format")]
    UnrecognizedInputFormat,
    #[error("ASCII input is empty")]
    EmptyAsciiInput,
    #[error("line {line}: expected at least PCR, template digest, and template name")]
    AsciiMissingColumns { line: usize },
    #[error("line {line}: invalid PCR index: {value}")]
    InvalidPcr { line: usize, value: String },
    #[error("line {line}: invalid template digest hex: {source}")]
    InvalidDigestHex {
        line: usize,
        #[source]
        source: hex::FromHexError,
    },
    #[error(
        "record {record}: template digest length does not match selected PCR hash algorithm {algorithm}: expected {expected} bytes, got {actual}"
    )]
    DigestLengthMismatch {
        record: usize,
        algorithm: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
    #[error("line {line}: template {template} cannot be rebuilt from ASCII fields")]
    UnsupportedAsciiTemplate { line: usize, template: String },
    #[error("line {line}: template {template} is missing field {field}")]
    MissingTemplateField {
        line: usize,
        template: String,
        field: &'static str,
    },
    #[error("line {line}: invalid template field {field}: {source}")]
    InvalidTemplateFieldHex {
        line: usize,
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
    #[error("line {line}: invalid digest field {field}")]
    InvalidDigestField { line: usize, field: &'static str },
    #[error("binary input truncated while reading {field} at offset {offset}")]
    BinaryTruncated { field: &'static str, offset: usize },
    #[error("binary input has trailing {bytes} byte(s) after the last complete record")]
    BinaryTrailingBytes { bytes: usize },
    #[error("no measurement records matched PCR {0}")]
    NoMatchingPcr(u32),
}

pub fn replay_measurements(
    input: &[u8],
    options: ReplayOptions,
) -> Result<Vec<u8>, ImaReplayError> {
    if options.count == Some(0) {
        return Ok(vec![0; options.algorithm.digest_len()]);
    }

    let records = parse_measurements(input, options.algorithm)?;
    replay_records(&records, options)
}

fn parse_measurements(
    input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<MeasurementRecord>, ImaReplayError> {
    if let Ok(text) = std::str::from_utf8(input) {
        if first_non_empty_line_looks_ascii(text) {
            return parse_ascii_measurements(text, algorithm);
        }
    }

    parse_binary_measurements(input, algorithm).map_err(|error| match error {
        ImaReplayError::BinaryTruncated { .. } | ImaReplayError::BinaryTrailingBytes { .. } => {
            error
        }
        _ => ImaReplayError::UnrecognizedInputFormat,
    })
}

fn first_non_empty_line_looks_ascii(text: &str) -> bool {
    text.lines().any(|line| {
        let columns = line.split_whitespace().take(3).collect::<Vec<_>>();
        columns.len() >= 3
            && columns[0].parse::<u32>().is_ok()
            && columns[1].bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn parse_ascii_measurements(
    text: &str,
    algorithm: HashAlgorithm,
) -> Result<Vec<MeasurementRecord>, ImaReplayError> {
    let mut records = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            continue;
        }

        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 3 {
            return Err(ImaReplayError::AsciiMissingColumns { line: line_number });
        }

        let pcr = columns[0]
            .parse::<u32>()
            .map_err(|_| ImaReplayError::InvalidPcr {
                line: line_number,
                value: columns[0].to_owned(),
            })?;
        let mut template_digest =
            hex::decode(columns[1]).map_err(|source| ImaReplayError::InvalidDigestHex {
                line: line_number,
                source,
            })?;

        if template_digest.len() != algorithm.digest_len() {
            template_digest = rebuild_ascii_template_digest(line_number, &columns, algorithm)?;
        }

        validate_digest_len(records.len() + 1, algorithm, template_digest.len())?;
        records.push(MeasurementRecord {
            pcr,
            template_digest,
        });
    }

    if records.is_empty() {
        return Err(ImaReplayError::EmptyAsciiInput);
    }

    Ok(records)
}

fn rebuild_ascii_template_digest(
    line: usize,
    columns: &[&str],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, ImaReplayError> {
    let template = columns[2];
    let fields = match template {
        "ima-ng" => vec![
            rebuild_digest_with_algo_field(line, columns, 3, "d-ng")?,
            rebuild_string_field(line, columns, 4, template, "n-ng")?,
        ],
        "ima-sig" => vec![
            rebuild_digest_with_algo_field(line, columns, 3, "d-ng")?,
            rebuild_string_field(line, columns, 4, template, "n-ng")?,
            rebuild_optional_hex_field(line, columns, 5, "sig")?,
        ],
        "ima-buf" => vec![
            rebuild_digest_with_algo_field(line, columns, 3, "d-ng")?,
            rebuild_string_field(line, columns, 4, template, "n-ng")?,
            rebuild_optional_hex_field(line, columns, 5, "buf")?,
        ],
        "ima-ngv2" => vec![
            rebuild_digest_with_type_and_algo_field(line, columns, 3, "d-ngv2")?,
            rebuild_string_field(line, columns, 4, template, "n-ng")?,
        ],
        "ima-sigv2" => vec![
            rebuild_digest_with_type_and_algo_field(line, columns, 3, "d-ngv2")?,
            rebuild_string_field(line, columns, 4, template, "n-ng")?,
            rebuild_optional_hex_field(line, columns, 5, "sig")?,
        ],
        _ => {
            return Err(ImaReplayError::UnsupportedAsciiTemplate {
                line,
                template: template.to_owned(),
            });
        }
    };

    let mut template_data = Vec::new();
    for field in fields {
        template_data.extend_from_slice(&(field.len() as u32).to_le_bytes());
        template_data.extend_from_slice(&field);
    }

    Ok(algorithm.digest(&template_data))
}

fn rebuild_digest_with_algo_field(
    line: usize,
    columns: &[&str],
    index: usize,
    field: &'static str,
) -> Result<Vec<u8>, ImaReplayError> {
    let value = columns
        .get(index)
        .ok_or_else(|| ImaReplayError::MissingTemplateField {
            line,
            template: columns[2].to_owned(),
            field,
        })?;
    let (algo, digest_hex) = value
        .split_once(':')
        .ok_or(ImaReplayError::InvalidDigestField { line, field })?;
    let digest =
        hex::decode(digest_hex).map_err(|source| ImaReplayError::InvalidTemplateFieldHex {
            line,
            field,
            source,
        })?;

    let mut data = Vec::with_capacity(algo.len() + 2 + digest.len());
    data.extend_from_slice(algo.as_bytes());
    data.extend_from_slice(b":\0");
    data.extend_from_slice(&digest);
    Ok(data)
}

fn rebuild_digest_with_type_and_algo_field(
    line: usize,
    columns: &[&str],
    index: usize,
    field: &'static str,
) -> Result<Vec<u8>, ImaReplayError> {
    let value = columns
        .get(index)
        .ok_or_else(|| ImaReplayError::MissingTemplateField {
            line,
            template: columns[2].to_owned(),
            field,
        })?;
    let (digest_type, rest) = value
        .split_once(':')
        .ok_or(ImaReplayError::InvalidDigestField { line, field })?;
    let (algo, digest_hex) = rest
        .split_once(':')
        .ok_or(ImaReplayError::InvalidDigestField { line, field })?;
    let digest =
        hex::decode(digest_hex).map_err(|source| ImaReplayError::InvalidTemplateFieldHex {
            line,
            field,
            source,
        })?;

    let mut data = Vec::with_capacity(digest_type.len() + algo.len() + 3 + digest.len());
    data.extend_from_slice(digest_type.as_bytes());
    data.push(b':');
    data.extend_from_slice(algo.as_bytes());
    data.extend_from_slice(b":\0");
    data.extend_from_slice(&digest);
    Ok(data)
}

fn rebuild_string_field(
    line: usize,
    columns: &[&str],
    index: usize,
    template: &str,
    field: &'static str,
) -> Result<Vec<u8>, ImaReplayError> {
    let value = columns
        .get(index)
        .ok_or_else(|| ImaReplayError::MissingTemplateField {
            line,
            template: template.to_owned(),
            field,
        })?;
    let mut data = Vec::with_capacity(value.len() + 1);
    data.extend_from_slice(value.as_bytes());
    data.push(0);
    Ok(data)
}

fn rebuild_optional_hex_field(
    line: usize,
    columns: &[&str],
    index: usize,
    field: &'static str,
) -> Result<Vec<u8>, ImaReplayError> {
    let Some(value) = columns.get(index) else {
        return Ok(Vec::new());
    };
    hex::decode(value).map_err(|source| ImaReplayError::InvalidTemplateFieldHex {
        line,
        field,
        source,
    })
}

fn parse_binary_measurements(
    input: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<MeasurementRecord>, ImaReplayError> {
    let mut offset = 0;
    let mut records = Vec::new();
    let digest_len = algorithm.digest_len();

    while offset < input.len() {
        let pcr = read_u32_le(input, &mut offset, "PCR index")?;
        let template_digest =
            read_bytes(input, &mut offset, digest_len, "template digest")?.to_vec();
        let template_name_len = read_u32_le(input, &mut offset, "template name length")? as usize;
        let _template_name = read_bytes(input, &mut offset, template_name_len, "template name")?;
        let template_data_len = read_u32_le(input, &mut offset, "template data length")? as usize;
        let _template_data = read_bytes(input, &mut offset, template_data_len, "template data")?;

        records.push(MeasurementRecord {
            pcr,
            template_digest,
        });
    }

    if records.is_empty() {
        return Err(ImaReplayError::UnrecognizedInputFormat);
    }

    Ok(records)
}

fn read_u32_le(
    input: &[u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<u32, ImaReplayError> {
    let bytes = read_bytes(input, offset, 4, field)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("u32 read has fixed length"),
    ))
}

fn read_bytes<'a>(
    input: &'a [u8],
    offset: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], ImaReplayError> {
    let end = offset
        .checked_add(len)
        .ok_or(ImaReplayError::BinaryTruncated {
            field,
            offset: *offset,
        })?;
    if end > input.len() {
        return Err(ImaReplayError::BinaryTruncated {
            field,
            offset: *offset,
        });
    }

    let bytes = &input[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn replay_records(
    records: &[MeasurementRecord],
    options: ReplayOptions,
) -> Result<Vec<u8>, ImaReplayError> {
    let mut pcr = vec![0; options.algorithm.digest_len()];
    let mut used = 0usize;

    if options.count == Some(0) {
        return Ok(pcr);
    }

    for (index, record) in records.iter().enumerate() {
        if record.pcr != options.pcr {
            continue;
        }

        validate_digest_len(index + 1, options.algorithm, record.template_digest.len())?;
        let mut data = Vec::with_capacity(pcr.len() + record.template_digest.len());
        data.extend_from_slice(&pcr);
        data.extend_from_slice(&record.template_digest);
        pcr = options.algorithm.digest(&data);
        used += 1;

        if options.count == Some(used) {
            break;
        }
    }

    if used == 0 {
        return Err(ImaReplayError::NoMatchingPcr(options.pcr));
    }

    Ok(pcr)
}

fn validate_digest_len(
    record: usize,
    algorithm: HashAlgorithm,
    actual: usize,
) -> Result<(), ImaReplayError> {
    let expected = algorithm.digest_len();
    if actual != expected {
        return Err(ImaReplayError::DigestLengthMismatch {
            record,
            algorithm,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_options() -> ReplayOptions {
        ReplayOptions {
            algorithm: HashAlgorithm::Sha256,
            pcr: 10,
            count: None,
        }
    }

    fn digest(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn extend_sha256(pcr: &[u8], digest: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(pcr);
        data.extend_from_slice(digest);
        Sha256::digest(&data).to_vec()
    }

    #[test]
    fn replays_ascii_measurements_for_target_pcr() {
        let first = digest(0x11);
        let second = digest(0x22);
        let skipped = digest(0x33);
        let input = format!(
            "10 {first} ima-ng sha256:abcd /bin/a\n11 {skipped} ima-ng sha256:abcd /bin/skip\n10 {second} ima-ng sha256:abcd /bin/b\n"
        );

        let actual = replay_measurements(input.as_bytes(), default_options()).unwrap();
        let pcr = vec![0; 32];
        let pcr = extend_sha256(&pcr, &[0x11; 32]);
        let expected = extend_sha256(&pcr, &[0x22; 32]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn count_limits_participating_records() {
        let first = digest(0x11);
        let second = digest(0x22);
        let input = format!(
            "10 {first} ima-ng sha256:abcd /bin/a\n10 {second} ima-ng sha256:abcd /bin/b\n"
        );
        let options = ReplayOptions {
            count: Some(1),
            ..default_options()
        };

        let actual = replay_measurements(input.as_bytes(), options).unwrap();
        let expected = extend_sha256(&vec![0; 32], &[0x11; 32]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn count_zero_outputs_initial_pcr() {
        let input = format!("10 {} ima-ng sha256:abcd /bin/a\n", digest(0x11));
        let options = ReplayOptions {
            count: Some(0),
            ..default_options()
        };

        let actual = replay_measurements(input.as_bytes(), options).unwrap();

        assert_eq!(actual, vec![0; 32]);
    }

    #[test]
    fn count_zero_does_not_require_parseable_input() {
        let options = ReplayOptions {
            count: Some(0),
            ..default_options()
        };

        let actual = replay_measurements(b"", options).unwrap();

        assert_eq!(actual, vec![0; 32]);
    }

    #[test]
    fn rebuilds_sha256_template_digest_from_ascii_ima_sig_fields() {
        let input = "10 8aa71d146be2b1a0a53cb603be22928f1b74ae17 ima-sig sha256:94326940137a8f59b369d1aa058bccce58cbda37e68be0f138ea45c2cb743a46 boot_aggregate\n";

        let actual = replay_measurements(input.as_bytes(), default_options()).unwrap();
        let expected_template_digest =
            hex::decode("cc1078d3b981e8ef52b3d4d9cffc2f27648d05947d4caa829e47f83fb8f8ed00")
                .unwrap();
        let expected = extend_sha256(&vec![0; 32], &expected_template_digest);

        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_mismatched_digest_when_ascii_template_is_unsupported() {
        let input = format!(
            "10 {} custom-template sha1:abcd /bin/a\n",
            hex::encode([0x11; 20])
        );

        let error = replay_measurements(input.as_bytes(), default_options()).unwrap_err();

        assert!(matches!(
            error,
            ImaReplayError::UnsupportedAsciiTemplate { .. }
        ));
    }

    #[test]
    fn replays_binary_measurements() {
        let mut input = Vec::new();
        input.extend_from_slice(&10u32.to_le_bytes());
        input.extend_from_slice(&[0x44; 32]);
        input.extend_from_slice(&6u32.to_le_bytes());
        input.extend_from_slice(b"ima-ng");
        input.extend_from_slice(&3u32.to_le_bytes());
        input.extend_from_slice(&[1, 2, 3]);

        let actual = replay_measurements(&input, default_options()).unwrap();
        let expected = extend_sha256(&vec![0; 32], &[0x44; 32]);

        assert_eq!(actual, expected);
    }
}
