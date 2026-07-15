//! Output formatting for CLI

use crate::{CliError, OutputFormat};
use serde::Serialize;
use tabled::{Table, settings::Style};
use std::io::{self, Write};

/// Print output in the specified format
pub fn print_output<T: Serialize>(value: &T, format: &OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Table => print_table(value),
        OutputFormat::Json => print_json(value),
        OutputFormat::JsonPretty => print_json_pretty(value),
        OutputFormat::Yaml => print_yaml(value),
        OutputFormat::Csv => print_csv(value),
    }
}

fn print_table<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_value(value)?;
    
    if let Some(array) = json.as_array() {
        if array.is_empty() {
            println!("(empty)");
            return Ok(());
        }
        
        // Convert to table
        let table = Table::new(array).with(Style::modern()).to_string();
        println!("{}", table);
    } else if let Some(object) = json.as_object() {
        // Single object - print as key-value table
        let mut rows = Vec::new();
        for (key, val) in object {
            rows.push(serde_json::json!({
                "Property": key,
                "Value": format_value(val),
            }));
        }
        
        let table = Table::new(rows).with(Style::modern()).to_string();
        println!("{}", table);
    } else {
        println!("{}", format_value(&json));
    }
    
    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_string(value)?;
    println!("{}", json);
    Ok(())
}

fn print_json_pretty<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{}", json);
    Ok(())
}

fn print_yaml<T: Serialize>(value: &T) -> Result<(), CliError> {
    let yaml = serde_yaml::to_string(value)?;
    println!("{}", yaml);
    Ok(())
}

fn print_csv<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_value(value)?;
    
    if let Some(array) = json.as_array() {
        if array.is_empty() {
            return Ok(());
        }
        
        // Write CSV header
        if let Some(first) = array.first().and_then(|v| v.as_object()) {
            let headers: Vec<&str> = first.keys().map(|k| k.as_str()).collect();
            println!("{}", headers.join(","));
            
            // Write rows
            for item in array {
                if let Some(obj) = item.as_object() {
                    let row: Vec<String> = headers.iter()
                        .map(|h| obj.get(*h).map(format_value).unwrap_or_default())
                        .collect();
                    println!("{}", row.join(","));
                }
            }
        }
    } else {
        return Err(CliError::InvalidInput("CSV output requires an array".into()));
    }
    
    Ok(())
}

fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Array(arr) => {
            format!("[{}]", arr.iter().map(format_value).collect::<Vec<_>>().join(", "))
        }
        serde_json::Value::Object(obj) => {
            format!("{{{}}}", obj.iter()
                .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                .collect::<Vec<_>>()
                .join(", "))
        }
    }
}

/// Output format enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Table,
    Json,
    #[serde(rename = "json-pretty")]
    JsonPretty,
    Yaml,
    Csv,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::JsonPretty => write!(f, "json-pretty"),
            OutputFormat::Yaml => write!(f, "yaml"),
            OutputFormat::Csv => write!(f, "csv"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "json-pretty" | "jsonpretty" => Ok(OutputFormat::JsonPretty),
            "yaml" => Ok(OutputFormat::Yaml),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}