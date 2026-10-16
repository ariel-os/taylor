//! PyO3 bindings exposing taylor's public Rust API as the `taylor._taylor` extension module.

use std::fs;
use std::path::{Path, PathBuf};

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;
use taylor::error::Error;
use taylor::manifest::SuitManifest;

create_exception!(
    taylor,
    TaylorError,
    PyException,
    "Base class for all taylor errors."
);
create_exception!(
    taylor,
    ManifestError,
    TaylorError,
    "The manifest JSON is malformed or uses unsupported members, commands, or parameters."
);
create_exception!(
    taylor,
    TemplateError,
    TaylorError,
    "A template or its variables couldn't be read or rendered."
);
create_exception!(
    taylor,
    SigningError,
    TaylorError,
    "The signing key couldn't be loaded or the envelope couldn't be signed."
);

fn to_py_err(err: Error) -> PyErr {
    let message = err.to_string();
    if matches!(err, Error::Signing(_)) {
        SigningError::new_err(message)
    } else {
        ManifestError::new_err(message)
    }
}

fn parse_manifest(manifest_json: &str) -> PyResult<SuitManifest> {
    taylor::parse::parse(&mut manifest_json.as_bytes()).map_err(to_py_err)
}

/// Encodes a JSON manifest as a bstr-wrapped `SUIT_Manifest`.
#[pyfunction]
fn encode_manifest(py: Python<'_>, manifest_json: String) -> PyResult<Bound<'_, PyBytes>> {
    let encoded = py.detach(|| {
        parse_manifest(&manifest_json).map(|manifest| taylor::encode::encode_manifest(&manifest))
    })?;
    Ok(PyBytes::new(py, &encoded))
}

/// Encodes a JSON manifest as a tag-107 `SUIT_Envelope`, signed when a key is given.
#[pyfunction]
#[pyo3(signature = (manifest_json, key_pem=None, key_path=None))]
fn build_envelope(
    py: Python<'_>,
    manifest_json: String,
    key_pem: Option<String>,
    key_path: Option<PathBuf>,
) -> PyResult<Bound<'_, PyBytes>> {
    let envelope = py.detach(|| build_envelope_bytes(&manifest_json, key_pem, key_path))?;
    Ok(PyBytes::new(py, &envelope))
}

fn build_envelope_bytes(
    manifest_json: &str,
    key_pem: Option<String>,
    key_path: Option<PathBuf>,
) -> PyResult<Vec<u8>> {
    let pem = match (key_pem, key_path) {
        (Some(_), Some(_)) => {
            return Err(PyValueError::new_err("pass key_pem or key_path, not both"));
        }
        (Some(pem), None) => Some(pem),
        (None, Some(path)) => Some(fs::read_to_string(&path).map_err(|e| {
            SigningError::new_err(format!(
                "failed to read signing key {}: {e}",
                path.display()
            ))
        })?),
        (None, None) => None,
    };
    let signer = pem
        .as_deref()
        .map(taylor::sign::load_signer)
        .transpose()
        .map_err(|e| SigningError::new_err(format!("invalid signing key: {e}")))?;
    let manifest = parse_manifest(manifest_json)?;
    taylor::envelope::build_envelope(manifest, signer.as_ref()).map_err(to_py_err)
}

/// Renders a minijinja template into manifest JSON from a JSON object of variables and/or a
/// JSON vars file; `variables_json` wins on key collisions.
#[pyfunction]
#[pyo3(signature = (template_path, variables_json=None, vars_file=None))]
fn render_template(
    py: Python<'_>,
    template_path: PathBuf,
    variables_json: Option<String>,
    vars_file: Option<PathBuf>,
) -> PyResult<String> {
    py.detach(|| render_template_text(&template_path, variables_json, vars_file))
}

fn render_template_text(
    template_path: &Path,
    variables_json: Option<String>,
    vars_file: Option<PathBuf>,
) -> PyResult<String> {
    let vars: Vec<(String, Value)> = match variables_json {
        None => Vec::new(),
        Some(json) => match serde_json::from_str::<Value>(&json) {
            Ok(Value::Object(map)) => map.into_iter().collect(),
            Ok(_) => return Err(PyValueError::new_err("variables must be a JSON object")),
            Err(e) => {
                return Err(PyValueError::new_err(format!(
                    "variables are not valid JSON: {e}"
                )));
            }
        },
    };
    let context = taylor::template::build_context(vars_file.as_deref(), &vars)
        .map_err(|e| TemplateError::new_err(e.to_string()))?;
    taylor::template::render(template_path, &context)
        .map_err(|e| TemplateError::new_err(e.to_string()))
}

/// Runs the `taylor` command-line interface in-process and returns its exit code.
#[pyfunction]
fn run_cli(py: Python<'_>, argv: Vec<PathBuf>) -> i32 {
    // `PathBuf` extraction goes through `os.fspath`, so both `str` and `os.PathLike` work.
    py.detach(|| taylor::cli::run(argv.into_iter().map(PathBuf::into_os_string)))
}

#[pymodule]
fn _taylor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("TaylorError", py.get_type::<TaylorError>())?;
    m.add("ManifestError", py.get_type::<ManifestError>())?;
    m.add("TemplateError", py.get_type::<TemplateError>())?;
    m.add("SigningError", py.get_type::<SigningError>())?;
    m.add_function(wrap_pyfunction!(encode_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(build_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(render_template, m)?)?;
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    Ok(())
}
