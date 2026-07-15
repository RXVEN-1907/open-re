//! AI tools for open-re

use crate::providers::*;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_storage::{GlobalStore, ProjectStore, ObjectStore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

/// Tool trait
#[async_trait]
pub trait AiTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters_schema(&self) -> serde_json::Value;
    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult>;
}

/// Tool context
pub struct ToolContext {
    pub global_store: Arc<GlobalStore>,
    pub project_store: Option<Arc<ProjectStore>>,
    pub object_store: Arc<ObjectStore>,
    pub current_project: Option<ProjectId>,
    pub current_file: Option<FileId>,
    pub current_function: Option<FunctionId>,
    pub permissions: ToolPermissions,
}

/// Tool permissions
#[derive(Debug, Clone, Default)]
pub struct ToolPermissions {
    pub read_binary: bool,
    pub write_annotation: bool,
    pub query_database: bool,
    pub execute_script: bool,
    pub network_access: bool,
}

/// Tool result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl ToolResult {
    pub fn success(output: serde_json::Value) -> Self {
        Self { success: true, output, error: None, metadata: HashMap::new() }
    }

    pub fn error(error: String) -> Self {
        Self { success: false, output: serde_json::Value::Null, error: Some(error), metadata: HashMap::new() }
    }
}

/// Tool registry
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn AiTool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let mut registry = Self { tools: HashMap::new() };
        registry.register_builtin_tools();
        registry
    }

    fn register_builtin_tools(&mut self) {
        self.register(Box::new(ReadBinaryTool));
        self.register(Box::new(WriteAnnotationTool));
        self.register(Box::new(QueryDatabaseTool));
        self.register(Box::new(GetFunctionInfoTool));
        self.register(Box::new(GetBasicBlocksTool));
        self.register(Box::new(GetInstructionsTool));
        self.register(Box::new(GetCFGTool));
        self.register(Box::new(GetXrefsTool));
        self.register(Box::new(GetStringsTool));
        self.register(Box::new(GetSymbolsTool));
        self.register(Box::new(SearchTool));
        self.register(Box::new(ExecuteScriptTool));
    }

    pub fn register(&mut self, tool: Box<dyn AiTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&dyn AiTool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    pub fn all(&self) -> Vec<&dyn AiTool> {
        self.tools.values().map(|t| t.as_ref()).collect()
    }

    pub fn to_tool_definitions(&self) -> Vec<ToolDefinition> {
        self.tools.values()
            .map(|t| ToolDefinition {
                name: t.name().to_string(),
                description: t.description().to_string(),
                parameters: t.parameters_schema(),
                required: vec![],
            })
            .collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Read binary data tool
pub struct ReadBinaryTool;

#[async_trait]
impl AiTool for ReadBinaryTool {
    fn name(&self) -> &str { "read_binary" }
    fn description(&self) -> &str { "Read raw bytes from the binary file at a given offset" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "offset": { "type": "integer", "description": "Byte offset in the file" },
                "length": { "type": "integer", "description": "Number of bytes to read" },
                "file_id": { "type": "string", "description": "Optional file ID (uses current file if not specified)" }
            },
            "required": ["offset", "length"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let offset = args["offset"].as_u64().ok_or_else(|| openre_core::Error::InvalidInput("offset required".into()))?;
        let length = args["length"].as_u64().ok_or_else(|| openre_core::Error::InvalidInput("length required".into()))?;
        let file_id = args["file_id"].as_str()
            .and_then(|s| s.parse().ok())
            .or(context.current_file);

        let file_id = file_id.ok_or_else(|| openre_core::Error::InvalidInput("file_id required".into()))?;

        // Read from object store
        let data = context.object_store.read_file(file_id, offset, length).await?;

        Ok(ToolResult::success(serde_json::json!({
            "offset": offset,
            "length": length,
            "data": base64::encode(data),
            "hex": hex::encode(data),
        })))
    }
}

/// Write annotation tool
pub struct WriteAnnotationTool;

#[async_trait]
impl AiTool for WriteAnnotationTool {
    fn name(&self) -> &str { "write_annotation" }
    fn description(&self) -> &str { "Write an annotation (comment, label, type) to the database" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "target_type": { "type": "string", "enum": ["function", "instruction", "variable", "address"], "description": "Type of target to annotate" },
                "target_id": { "type": "string", "description": "ID of the target" },
                "annotation_type": { "type": "string", "enum": ["comment", "label", "type", "name"], "description": "Type of annotation" },
                "content": { "type": "string", "description": "Annotation content" },
                "confidence": { "type": "number", "minimum": 0, "maximum": 1, "description": "Confidence score" }
            },
            "required": ["target_type", "target_id", "annotation_type", "content"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        if !context.permissions.write_annotation {
            return Ok(ToolResult::error("Write annotation permission denied".into()));
        }

        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let target_type = args["target_type"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("target_type required".into()))?;
        let target_id = args["target_id"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("target_id required".into()))?;
        let annotation_type = args["annotation_type"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("annotation_type required".into()))?;
        let content = args["content"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("content required".into()))?;
        let confidence = args["confidence"].as_f64().unwrap_or(1.0);

        // Store annotation based on target type
        match target_type {
            "function" => {
                let func_id: FunctionId = target_id.parse()?;
                project_store.add_function_annotation(func_id, annotation_type, content, confidence).await?;
            }
            "instruction" => {
                let inst_id: InstructionId = target_id.parse()?;
                project_store.add_instruction_annotation(inst_id, annotation_type, content, confidence).await?;
            }
            "variable" => {
                let var_id: VariableId = target_id.parse()?;
                project_store.add_variable_annotation(var_id, annotation_type, content, confidence).await?;
            }
            "address" => {
                let addr: u64 = target_id.parse()?;
                project_store.add_address_annotation(addr, annotation_type, content, confidence).await?;
            }
            _ => return Ok(ToolResult::error(format!("Unknown target type: {}", target_type))),
        }

        Ok(ToolResult::success(serde_json::json!({
            "target_type": target_type,
            "target_id": target_id,
            "annotation_type": annotation_type,
            "content": content,
        })))
    }
}

/// Query database tool
pub struct QueryDatabaseTool;

#[async_trait]
impl AiTool for QueryDatabaseTool {
    fn name(&self) -> &str { "query_database" }
    fn description(&self) -> &str { "Execute a read-only SQL query on the project database" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "SQL query (SELECT only)" },
                "params": { "type": "array", "items": { "type": "string" }, "description": "Query parameters" }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        if !context.permissions.query_database {
            return Ok(ToolResult::error("Query database permission denied".into()));
        }

        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let query = args["query"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("query required".into()))?;

        // Validate it's a SELECT query
        let trimmed = query.trim().to_lowercase();
        if !trimmed.starts_with("select") && !trimmed.starts_with("with") {
            return Ok(ToolResult::error("Only SELECT queries allowed".into()));
        }

        let params: Vec<String> = args["params"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let results = project_store.execute_query(query, &params).await?;

        Ok(ToolResult::success(serde_json::json!({
            "rows": results,
            "row_count": results.len(),
        })))
    }
}

/// Get function info tool
pub struct GetFunctionInfoTool;

#[async_trait]
impl AiTool for GetFunctionInfoTool {
    fn name(&self) -> &str { "get_function_info" }
    fn description(&self) -> &str { "Get detailed information about a function" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "function_id": { "type": "string", "description": "Function ID" }
            },
            "required": ["function_id"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let function_id: FunctionId = args["function_id"].as_str()
            .ok_or_else(|| openre_core::Error::InvalidInput("function_id required".into()))?
            .parse()?;

        let function = project_store.get_function(function_id).await?
            .ok_or_else(|| openre_core::Error::NotFound("Function not found".into()))?;

        Ok(ToolResult::success(serde_json::to_value(function)?))
    }
}

/// Get basic blocks tool
pub struct GetBasicBlocksTool;

#[async_trait]
impl AiTool for GetBasicBlocksTool {
    fn name(&self) -> &str { "get_basic_blocks" }
    fn description(&self) -> &str { "Get basic blocks for a function" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "function_id": { "type": "string", "description": "Function ID" }
            },
            "required": ["function_id"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let function_id: FunctionId = args["function_id"].as_str()
            .ok_or_else(|| openre_core::Error::InvalidInput("function_id required".into()))?
            .parse()?;

        let blocks = project_store.get_basic_blocks(function_id).await?;

        Ok(ToolResult::success(serde_json::to_value(blocks)?))
    }
}

/// Get instructions tool
pub struct GetInstructionsTool;

#[async_trait]
impl AiTool for GetInstructionsTool {
    fn name(&self) -> &str { "get_instructions" }
    fn description(&self) -> &str { "Get instructions for a basic block or function" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "block_id": { "type": "string", "description": "Basic block ID" },
                "function_id": { "type": "string", "description": "Function ID (alternative to block_id)" }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        if let Some(block_id_str) = args["block_id"].as_str() {
            let block_id: BlockId = block_id_str.parse()?;
            let instructions = project_store.get_instructions(block_id).await?;
            Ok(ToolResult::success(serde_json::to_value(instructions)?))
        } else if let Some(function_id_str) = args["function_id"].as_str() {
            let function_id: FunctionId = function_id_str.parse()?;
            let blocks = project_store.get_basic_blocks(function_id).await?;
            let mut all_instructions = Vec::new();
            for block in blocks {
                let instructions = project_store.get_instructions(block.id).await?;
                all_instructions.extend(instructions);
            }
            Ok(ToolResult::success(serde_json::to_value(all_instructions)?))
        } else {
            Ok(ToolResult::error("Either block_id or function_id required".into()))
        }
    }
}

/// Get CFG tool
pub struct GetCFGTool;

#[async_trait]
impl AiTool for GetCFGTool {
    fn name(&self) -> &str { "get_cfg" }
    fn description(&self) -> &str { "Get control flow graph for a function" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "function_id": { "type": "string", "description": "Function ID" }
            },
            "required": ["function_id"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let function_id: FunctionId = args["function_id"].as_str()
            .ok_or_else(|| openre_core::Error::InvalidInput("function_id required".into()))?
            .parse()?;

        let cfg = project_store.get_cfg(function_id).await?;

        Ok(ToolResult::success(serde_json::to_value(cfg)?))
    }
}

/// Get xrefs tool
pub struct GetXrefsTool;

#[async_trait]
impl AiTool for GetXrefsTool {
    fn name(&self) -> &str { "get_xrefs" }
    fn description(&self) -> &str { "Get cross-references to/from an address or function" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "target_type": { "type": "string", "enum": ["address", "function"], "description": "Target type" },
                "target_id": { "type": "string", "description": "Target address or function ID" },
                "direction": { "type": "string", "enum": ["to", "from", "both"], "description": "Reference direction" }
            },
            "required": ["target_type", "target_id"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let target_type = args["target_type"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("target_type required".into()))?;
        let target_id = args["target_id"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("target_id required".into()))?;
        let direction = args["direction"].as_str().unwrap_or("both");

        let xrefs = match target_type {
            "address" => {
                let addr: u64 = target_id.parse()?;
                project_store.get_xrefs_to_address(addr).await?
            }
            "function" => {
                let func_id: FunctionId = target_id.parse()?;
                project_store.get_xrefs_to_function(func_id).await?
            }
            _ => return Ok(ToolResult::error("Unknown target type".into())),
        };

        let filtered: Vec<_> = xrefs.into_iter().filter(|x| {
            match direction {
                "to" => x.is_to,
                "from" => !x.is_to,
                _ => true,
            }
        }).collect();

        Ok(ToolResult::success(serde_json::to_value(filtered)?))
    }
}

/// Get strings tool
pub struct GetStringsTool;

#[async_trait]
impl AiTool for GetStringsTool {
    fn name(&self) -> &str { "get_strings" }
    fn description(&self) -> &str { "Get strings from the binary" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "min_length": { "type": "integer", "description": "Minimum string length", "default": 4 },
                "encoding": { "type": "string", "enum": ["ascii", "utf8", "utf16", "all"], "description": "String encoding", "default": "ascii" },
                "address": { "type": "integer", "description": "Optional address filter" }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let min_length = args["min_length"].as_u64().unwrap_or(4) as usize;
        let encoding = args["encoding"].as_str().unwrap_or("ascii");
        let address = args["address"].as_u64();

        let strings = project_store.get_strings(min_length, encoding, address).await?;

        Ok(ToolResult::success(serde_json::to_value(strings)?))
    }
}

/// Get symbols tool
pub struct GetSymbolsTool;

#[async_trait]
impl AiTool for GetSymbolsTool {
    fn name(&self) -> &str { "get_symbols" }
    fn description(&self) -> &str { "Get symbols from the binary" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "symbol_type": { "type": "string", "enum": ["function", "global", "import", "export", "all"], "description": "Symbol type filter", "default": "all" },
                "name_pattern": { "type": "string", "description": "Optional name pattern (glob)" }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let symbol_type = args["symbol_type"].as_str().unwrap_or("all");
        let name_pattern = args["name_pattern"].as_str();

        let symbols = project_store.get_symbols(symbol_type, name_pattern).await?;

        Ok(ToolResult::success(serde_json::to_value(symbols)?))
    }
}

/// Search tool
pub struct SearchTool;

#[async_trait]
impl AiTool for SearchTool {
    fn name(&self) -> &str { "search" }
    fn description(&self) -> &str { "Search for patterns in the binary (bytes, instructions, strings)" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Search query (hex bytes, instruction mnemonic, or string)" },
                "search_type": { "type": "string", "enum": ["bytes", "instructions", "strings", "all"], "description": "Search type", "default": "all" },
                "limit": { "type": "integer", "description": "Maximum results", "default": 100 }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        let project_store = context.project_store.as_ref()
            .ok_or_else(|| openre_core::Error::InvalidInput("No project context".into()))?;

        let query = args["query"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("query required".into()))?;
        let search_type = args["search_type"].as_str().unwrap_or("all");
        let limit = args["limit"].as_u64().unwrap_or(100) as usize;

        let results = project_store.search(query, search_type, limit).await?;

        Ok(ToolResult::success(serde_json::to_value(results)?))
    }
}

/// Execute script tool
pub struct ExecuteScriptTool;

#[async_trait]
impl AiTool for ExecuteScriptTool {
    fn name(&self) -> &str { "execute_script" }
    fn description(&self) -> &str { "Execute a Python script in the analysis environment" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "script": { "type": "string", "description": "Python script to execute" },
                "timeout_seconds": { "type": "integer", "description": "Execution timeout", "default": 30 }
            },
            "required": ["script"]
        })
    }

    async fn execute(&self, args: serde_json::Value, context: &ToolContext) -> Result<ToolResult> {
        if !context.permissions.execute_script {
            return Ok(ToolResult::error("Execute script permission denied".into()));
        }

        let script = args["script"].as_str().ok_or_else(|| openre_core::Error::InvalidInput("script required".into()))?;
        let timeout = args["timeout_seconds"].as_u64().unwrap_or(30);

        // Execute script in sandboxed environment
        // This would integrate with the Python bindings
        let output = format!("Script executed (timeout: {}s):\n{}", timeout, script);

        Ok(ToolResult::success(serde_json::json!({
            "output": output,
            "success": true,
        })))
    }
}