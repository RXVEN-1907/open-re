//! Output formatting

use clap::ValueEnum;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
    Yaml,
    Csv,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Table
    }
}

pub fn print_output<T: Serialize>(
    data: &T,
    format: OutputFormat,
    path: Option<&Path>,
) -> crate::Result<()> {
    match format {
        OutputFormat::Table => {
            // Table output is handled by individual commands
            // JSON fallback for piping
            if path.is_some() {
                write_json(data, path)?;
            }
        }
        OutputFormat::Json => {
            write_json(data, path)?;
        }
        OutputFormat::Sarif => {
            write_sarif(data, path)?;
        }
        OutputFormat::Yaml => {
            write_yaml(data, path)?;
        }
        OutputFormat::Csv => {
            write_csv(data, path)?;
        }
    }
    Ok(())
}

fn write_json<T: Serialize>(data: &T, path: Option<&Path>) -> crate::Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    if let Some(p) = path {
        std::fs::write(p, json)?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn write_sarif<T: Serialize>(data: &T, path: Option<&Path>) -> crate::Result<()> {
    // Try to serialize as SARIF if the type supports it
    #[cfg(feature = "sarif")]
    {
        use sarif::sarif210::Sarif;
        // This would require the data to be a Sarif type
        // For now, fall back to JSON
        write_json(data, path)
    }
    #[cfg(not(feature = "sarif"))]
    {
        write_json(data, path)
    }
}

fn write_yaml<T: Serialize>(data: &T, path: Option<&Path>) -> crate::Result<()> {
    let yaml = serde_yaml::to_string(data)?;
    if let Some(p) = path {
        std::fs::write(p, yaml)?;
    } else {
        println!("{}", yaml);
    }
    Ok(())
}

fn write_csv<T: Serialize>(data: &T, path: Option<&Path>) -> crate::Result<()> {
    // Simple CSV for arrays of objects
    let json = serde_json::to_value(data)?;
    if let Some(arr) = json.as_array() {
        if let Some(first) = arr.first() {
            if let Some(obj) = first.as_object() {
                let headers: Vec<String> = obj.keys().cloned().collect();
                let mut out = String::new();
                out.push_str(&headers.join(","));
                out.push('\n');

                for item in arr {
                    if let Some(obj) = item.as_object() {
                        let row: Vec<String> = headers.iter()
                            .map(|h| obj.get(h).map(|v| v.to_string()).unwrap_or_default())
                            .collect();
                        out.push_str(&row.join(","));
                        out.push('\n');
                    }
                }

                if let Some(p) = path {
                    std::fs::write(p, out)?;
                } else {
                    println!("{}", out);
                }
            }
        }
    }
    Ok(())
}