//! Renders a [minijinja](https://docs.rs/minijinja) template into a JSON manifest description,
//! for build pipelines that need to inject values (vendor/class IDs, version numbers, digests,
//! ...) at build time rather than committing them into a static JSON file.

use std::fmt;
use std::fs;
use std::path::Path;

use minijinja::{Environment, UndefinedBehavior};
use serde_json::{Map, Value};

/// Failure rendering a template or assembling its variable context.
#[derive(Debug)]
pub enum Error {
    /// The template file, or a `--vars-file`, couldn't be read.
    Io(std::io::Error),
    /// A `--vars-file` wasn't valid JSON, or wasn't a JSON object at its top level.
    InvalidVarsFile(String),
    /// The template references one or more variables that weren't supplied.
    MissingVariables(Vec<String>),
    /// The template failed to parse or render.
    Render(minijinja::Error),
    /// The template rendered successfully, but the result isn't valid JSON.
    InvalidOutput(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::InvalidVarsFile(msg) => write!(f, "invalid vars file: {msg}"),
            Error::MissingVariables(names) => {
                write!(
                    f,
                    "template references undefined variable(s): {}",
                    names.join(", ")
                )
            }
            Error::Render(e) => write!(f, "template render error: {e}"),
            Error::InvalidOutput(e) => write!(f, "rendered template isn't valid JSON: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Parses a single `--var KEY=VALUE` argument, inferring `bool`/`i64`/`f64` and falling back to
/// a string when none of those match. Also usable directly as a clap `value_parser`.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use taylor::template::parse_var;
///
/// assert_eq!(parse_var("image_size=1024").unwrap(), ("image_size".to_string(), json!(1024)));
/// assert_eq!(parse_var("strict=true").unwrap(), ("strict".to_string(), json!(true)));
/// assert_eq!(
///     parse_var("vendor_id=67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
///     ("vendor_id".to_string(), json!("67e55044-10b1-426f-9247-bb680e5fe0c8"))
/// );
/// assert!(parse_var("no-equals-sign").is_err());
/// ```
pub fn parse_var(s: &str) -> Result<(String, Value), String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid KEY=VALUE: no `=` found in `{s}`"))?;

    let value = if let Ok(b) = value.parse::<bool>() {
        Value::Bool(b)
    } else if let Ok(i) = value.parse::<i64>() {
        Value::Number(i.into())
    } else if let Ok(f) = value.parse::<f64>() {
        serde_json::Number::from_f64(f)
            .map_or_else(|| Value::String(value.to_string()), Value::Number)
    } else {
        Value::String(value.to_string())
    };

    Ok((key.to_string(), value))
}

/// Builds the template rendering context: a `vars_file` JSON object (if any) overlaid with
/// `vars`, where `vars` wins on key collisions.
///
/// # Errors
///
/// Returns [`Error::Io`] if `vars_file` can't be read, or [`Error::InvalidVarsFile`] if it isn't
/// a JSON object.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use taylor::template::build_context;
///
/// let vars = vec![("image_size".to_string(), json!(2048))];
/// let ctx = build_context(None, &vars).unwrap();
/// assert_eq!(ctx, json!({ "image_size": 2048 }));
/// ```
pub fn build_context(vars_file: Option<&Path>, vars: &[(String, Value)]) -> Result<Value, Error> {
    let mut context = match vars_file {
        Some(path) => {
            let contents = fs::read_to_string(path)?;
            let parsed: Value = serde_json::from_str(&contents)
                .map_err(|e| Error::InvalidVarsFile(format!("{path:?}: {e}")))?;
            match parsed {
                Value::Object(map) => map,
                _ => {
                    return Err(Error::InvalidVarsFile(format!(
                        "{path:?}: top level must be a JSON object"
                    )));
                }
            }
        }
        None => Map::new(),
    };

    for (key, value) in vars {
        context.insert(key.clone(), value.clone());
    }

    Ok(Value::Object(context))
}

/// Renders the template at `template_path` with `context`, then validates that the result is
/// well-formed JSON.
///
/// Before rendering, every top-level variable the template references (per minijinja's static
/// [`Template::undeclared_variables`](minijinja::Template::undeclared_variables) analysis) is
/// checked against `context`; any that's missing fails fast with [`Error::MissingVariables`].
/// This check exists because filters like `tojson` serialize an undefined value as JSON `null`
/// rather than erroring, even under [`UndefinedBehavior::Strict`].
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use taylor::template::render;
///
/// let path = std::env::temp_dir().join("taylor_template_doctest.jinja");
/// std::fs::write(&path, r#"{"vendor-id": {{ vendor_id | tojson }}}"#).unwrap();
///
/// let rendered = render(&path, &json!({ "vendor_id": "67e55044-10b1-426f-9247-bb680e5fe0c8" })).unwrap();
/// assert_eq!(rendered, r#"{"vendor-id": "67e55044-10b1-426f-9247-bb680e5fe0c8"}"#);
///
/// assert!(render(&path, &json!({})).is_err());
///
/// std::fs::remove_file(&path).unwrap();
/// ```
pub fn render(template_path: &Path, context: &Value) -> Result<String, Error> {
    let source = fs::read_to_string(template_path)?;

    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.add_template("template", &source)
        .map_err(Error::Render)?;
    let tmpl = env.get_template("template").map_err(Error::Render)?;

    let available: std::collections::HashSet<&str> = match context {
        Value::Object(map) => map.keys().map(String::as_str).collect(),
        _ => Default::default(),
    };
    let mut missing: Vec<String> = tmpl
        .undeclared_variables(false)
        .into_iter()
        .filter(|name| !available.contains(name.as_str()))
        .collect();
    if !missing.is_empty() {
        missing.sort();
        return Err(Error::MissingVariables(missing));
    }

    let rendered = tmpl.render(context).map_err(Error::Render)?;

    serde_json::from_str::<Value>(&rendered).map_err(Error::InvalidOutput)?;

    Ok(rendered)
}
