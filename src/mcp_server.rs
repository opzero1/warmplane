use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
};

use anyhow::Result;
use rmcp::{
    model::{
        AnnotateAble, CallToolRequestParams, CallToolResult, Content, GetPromptRequestParams,
        GetPromptResult, ListResourcesResult, ListToolsResult, Prompt, RawResource,
        ReadResourceRequestParams, ReadResourceResult, ServerCapabilities, ServerInfo, Tool,
    },
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde_json::{json, Map, Value};
use tokio::sync::oneshot;

use crate::{
    config::McpConfig,
    daemon::{initialize_state, AppState, CapabilityMeta, ServerMsg, UpstreamCallError},
};

const TOOL_CAPABILITIES_LIST: &str = "capabilities_list";
const TOOL_CAPABILITY_FIND: &str = "capability_find";
const TOOL_CAPABILITY_DESCRIBE: &str = "capability_describe";
const TOOL_CAPABILITY_CALL: &str = "capability_call";
const TOOL_RESOURCES_LIST: &str = "resources_list";
const TOOL_RESOURCE_READ: &str = "resource_read";
const TOOL_PROMPTS_LIST: &str = "prompts_list";
const TOOL_PROMPT_GET: &str = "prompt_get";

static TRACE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct FacadeMcpServer {
    state: AppState,
}

impl ServerHandler for FacadeMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
            instructions: Some(
                "Warmplane MCP facade server with deterministic tools/resources/prompts surfaces"
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        let tools = facade_tools();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let args = request.arguments.unwrap_or_default();

        let output = match request.name.as_ref() {
            TOOL_CAPABILITIES_LIST => {
                self.list_capabilities_value(
                    args.get("server").and_then(Value::as_str).map(ToString::to_string),
                    args.get("query").and_then(Value::as_str).map(ToString::to_string),
                    args.get("limit").and_then(Value::as_u64),
                )
                .await
            }
            TOOL_CAPABILITY_FIND => {
                let Some(server) = args.get("server").and_then(Value::as_str) else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'server'",
                    )));
                };
                let Some(query) = args.get("query").and_then(Value::as_str) else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'query'",
                    )));
                };
                self.find_capability_value(
                    server.to_string(),
                    query.to_string(),
                    args.get("limit").and_then(Value::as_u64),
                )
                .await
            }
            TOOL_CAPABILITY_DESCRIBE => {
                let Some(id) = args.get("id").and_then(Value::as_str) else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'id'",
                    )));
                };
                self.describe_capability_value(id.to_string()).await
            }
            TOOL_CAPABILITY_CALL => {
                let Some(capability_id) = args.get("capability_id").and_then(Value::as_str) else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'capability_id'",
                    )));
                };
                let Some(call_args) = args.get("args") else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'args'",
                    )));
                };
                if !call_args.is_object() {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "'args' must be a JSON object",
                    )));
                }
                let request_id = args
                    .get("request_id")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                self.call_capability_value(capability_id.to_string(), call_args.clone(), request_id)
                    .await
            }
            TOOL_RESOURCES_LIST => self.list_resources_value().await,
            TOOL_RESOURCE_READ => {
                let Some(resource_id) = args.get("resource_id").and_then(Value::as_str) else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'resource_id'",
                    )));
                };
                let request_id = args
                    .get("request_id")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                self.read_resource_value(resource_id.to_string(), request_id)
                    .await
            }
            TOOL_PROMPTS_LIST => self.list_prompts_value().await,
            TOOL_PROMPT_GET => {
                let Some(prompt_id) = args.get("prompt_id").and_then(Value::as_str) else {
                    return Ok(CallToolResult::structured_error(invalid_args(
                        "Missing required field 'prompt_id'",
                    )));
                };
                let request_id = args
                    .get("request_id")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let arguments = args.get("arguments").cloned();
                self.get_prompt_value(prompt_id.to_string(), arguments, request_id)
                    .await
            }
            _ => {
                return Err(McpError::invalid_params(
                    format!("Unknown tool '{}'.", request.name),
                    None,
                ));
            }
        };

        match output {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListResourcesResult, McpError> {
        let items = self
            .state
            .resources
            .values()
            .map(|r| {
                RawResource {
                    uri: r.uri.clone(),
                    name: r.name.clone(),
                    title: None,
                    description: r.description.clone(),
                    mime_type: r.mime_type.clone(),
                    size: None,
                    icons: None,
                    meta: None,
                }
                .no_annotation()
            })
            .collect::<Vec<_>>();
        Ok(ListResourcesResult::with_all_items(items))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ReadResourceResult, McpError> {
        let Some((_, meta)) = self
            .state
            .resources
            .iter()
            .find(|(_, m)| m.uri == request.uri)
        else {
            return Err(McpError::invalid_params(
                format!("Resource URI '{}' not found", request.uri),
                None,
            ));
        };

        let tx = self
            .state
            .servers
            .get(&meta.server)
            .ok_or_else(|| McpError::internal_error("Target server unreachable", None))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ServerMsg::ReadResource {
            uri: meta.uri.clone(),
            reply: reply_tx,
        })
        .await
        .map_err(|_| McpError::internal_error("Server mailbox closed", None))?;

        match reply_rx.await {
            Ok(Ok(value)) => serde_json::from_value(value).map_err(|e| {
                McpError::internal_error(format!("Invalid resource payload: {e}"), None)
            }),
            Ok(Err(UpstreamCallError::Timeout)) => {
                Err(McpError::internal_error("Resource read timed out", None))
            }
            Ok(Err(UpstreamCallError::Upstream(err))) => Err(McpError::internal_error(err, None)),
            Err(_) => Err(McpError::internal_error("Actor task died", None)),
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ListPromptsResult, McpError> {
        let prompts = self
            .state
            .prompts
            .values()
            .map(|p| Prompt {
                name: p.name.clone(),
                title: p.title.clone(),
                description: p.description.clone(),
                arguments: serde_json::from_value(Value::Array(p.arguments.clone())).ok(),
                icons: None,
                meta: None,
            })
            .collect::<Vec<_>>();
        Ok(rmcp::model::ListPromptsResult::with_all_items(prompts))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<GetPromptResult, McpError> {
        let Some((_, prompt_meta)) = self
            .state
            .prompts
            .iter()
            .find(|(_, p)| p.name == request.name)
        else {
            return Err(McpError::invalid_params(
                format!("Prompt '{}' not found", request.name),
                None,
            ));
        };

        let tx = self
            .state
            .servers
            .get(&prompt_meta.server)
            .ok_or_else(|| McpError::internal_error("Target server unreachable", None))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ServerMsg::GetPrompt {
            name: request.name,
            arguments: request.arguments,
            reply: reply_tx,
        })
        .await
        .map_err(|_| McpError::internal_error("Server mailbox closed", None))?;

        match reply_rx.await {
            Ok(Ok(value)) => serde_json::from_value(value).map_err(|e| {
                McpError::internal_error(format!("Invalid prompt payload: {e}"), None)
            }),
            Ok(Err(UpstreamCallError::Timeout)) => {
                Err(McpError::internal_error("Prompt get timed out", None))
            }
            Ok(Err(UpstreamCallError::Upstream(err))) => Err(McpError::internal_error(err, None)),
            Err(_) => Err(McpError::internal_error("Actor task died", None)),
        }
    }
}

impl FacadeMcpServer {
    fn capability_arg_fields(meta: &CapabilityMeta) -> (Vec<String>, Vec<String>) {
        let Some(props) = meta
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
        else {
            return (vec![], vec![]);
        };
        let required: Vec<String> = meta
            .input_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|items: &Vec<Value>| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let optional = props
            .keys()
            .filter(|key| !required.iter().any(|item| item == key.as_str()))
            .cloned()
            .collect::<Vec<_>>();

        (required, optional)
    }

    fn capability_score(id: &str, meta: &CapabilityMeta, query: &str) -> i32 {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return 0;
        }
        let id_l = id.to_lowercase();
        let server_l = meta.server.to_lowercase();
        let tool_l = meta.tool.to_lowercase();
        let summary_l = meta.summary.to_lowercase();
        let mut score = 0;
        if id_l == query || tool_l == query {
            score += 100;
        }
        if id_l.contains(&query) {
            score += 50;
        }
        if tool_l.contains(&query) {
            score += 40;
        }
        if summary_l.contains(&query) {
            score += 20;
        }

        for token in query
            .split(|char: char| !char.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
        {
            if server_l.contains(token) {
                score += 8;
            }
            if tool_l.contains(token) {
                score += 12;
            }
            if id_l.contains(token) {
                score += 12;
            }
            if summary_l.contains(token) {
                score += 6;
            }
        }

        score
    }

    async fn list_capabilities_value(
        &self,
        server: Option<String>,
        query: Option<String>,
        limit: Option<u64>,
    ) -> std::result::Result<Value, String> {
        let server = server.map(|value| value.to_lowercase());
        let query = query.map(|value| value.to_lowercase());
        let mut capabilities = self
            .state
            .capabilities
            .iter()
            .filter(|(id, meta)| {
                let server_matches = server
                    .as_ref()
                    .map(|value| meta.server.eq_ignore_ascii_case(value))
                    .unwrap_or(true);
                if !server_matches {
                    return false;
                }

                query
                    .as_ref()
                    .map(|value| {
                        id.to_lowercase().contains(value)
                            || meta.server.to_lowercase().contains(value)
                            || meta.tool.to_lowercase().contains(value)
                            || meta.summary.to_lowercase().contains(value)
                    })
                    .unwrap_or(true)
            })
            .map(|(id, meta)| {
                json!({
                    "id": id,
                    "summary": meta.summary,
                    "server": meta.server,
                    "tool": meta.tool,
                    "tags": meta.tags,
                })
            })
            .collect::<Vec<_>>();
        let mut server_readiness = self
            .state
            .server_readiness
            .iter()
            .filter(|(name, _)| {
                server
                    .as_ref()
                    .map(|value| name.eq_ignore_ascii_case(value))
                    .unwrap_or(true)
            })
            .map(|(server, readiness)| {
                json!({
                    "server": server,
                    "code": readiness.code,
                    "message": readiness.message,
                    "retryable": readiness.retryable,
                })
            })
            .collect::<Vec<_>>();

        capabilities.sort_by(|a, b| {
            a.get("id")
                .and_then(|v| v.as_str())
                .cmp(&b.get("id").and_then(|v| v.as_str()))
        });
        server_readiness.sort_by(|a, b| {
            a.get("server")
                .and_then(|v| v.as_str())
                .cmp(&b.get("server").and_then(|v| v.as_str()))
        });
        if let Some(limit) = limit {
            capabilities.truncate(limit.clamp(1, 100) as usize);
        }

        Ok(json!({
            "version": "v1",
            "capabilities": capabilities,
            "server_readiness": server_readiness,
        }))
    }

    async fn find_capability_value(
        &self,
        server: String,
        query: String,
        limit: Option<u64>,
    ) -> std::result::Result<Value, String> {
        let server_l = server.to_lowercase();
        let mut matches = self
            .state
            .capabilities
            .iter()
            .filter(|(_, meta)| meta.server.eq_ignore_ascii_case(&server_l))
            .map(|(id, meta)| {
                let score = Self::capability_score(id, meta, &query);
                let (required_fields, optional_fields) = Self::capability_arg_fields(meta);
                (
                    score,
                    json!({
                        "id": id,
                        "server": meta.server,
                        "tool": meta.tool,
                        "summary": meta.summary,
                        "required_fields": required_fields,
                        "optional_fields": optional_fields,
                    }),
                )
            })
            .filter(|(score, _)| *score > 0)
            .collect::<Vec<_>>();

        matches.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| {
            left.1
                .get("id")
                .and_then(Value::as_str)
                .cmp(&right.1.get("id").and_then(Value::as_str))
        }));

        let limit = limit.unwrap_or(8).clamp(1, 20) as usize;
        let matches = matches
            .into_iter()
            .take(limit)
            .map(|(_, value)| value)
            .collect::<Vec<_>>();

        Ok(json!({
            "version": "v1",
            "server": server,
            "query": query,
            "matches": matches,
        }))
    }

    async fn describe_capability_value(&self, id: String) -> std::result::Result<Value, String> {
        match self.state.capabilities.get(&id) {
            Some(meta) => Ok(json!({
                "version": "v1",
                "capability": {
                    "id": id,
                    "server": meta.server,
                    "tool": meta.tool,
                    "description": meta.description,
                    "input_schema": meta.input_schema,
                    "examples": meta.examples,
                }
            })),
            None => Ok(error_envelope(
                next_trace_id(),
                None,
                "TOOL_NOT_FOUND",
                format!("Capability '{}' not found", id),
                false,
            )),
        }
    }

    async fn call_capability_value(
        &self,
        capability_id: String,
        args: Value,
        request_id: Option<String>,
    ) -> std::result::Result<Value, String> {
        let trace_id = next_trace_id();
        if !self.state.policy.allows(&capability_id) {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "INVALID_ARGS",
                format!("Capability '{}' blocked by policy", capability_id),
                false,
            ));
        }

        let Some(meta) = self.state.capabilities.get(&capability_id) else {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "TOOL_NOT_FOUND",
                format!("Capability '{}' not found", capability_id),
                false,
            ));
        };

        let Some(tx) = self.state.servers.get(&meta.server) else {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "SERVER_UNREACHABLE",
                format!("Server '{}' is unreachable", meta.server),
                true,
            ));
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if tx
            .send(ServerMsg::CallTool {
                name: meta.tool.clone(),
                params: args,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "SERVER_UNREACHABLE",
                format!("Server '{}' mailbox is closed", meta.server),
                true,
            ));
        }

        match reply_rx.await {
            Ok(Ok(data)) => Ok(json!({
                "ok": true,
                "request_id": request_id,
                "trace_id": trace_id,
                "data": data,
                "error": null,
            })),
            Ok(Err(UpstreamCallError::Timeout)) => Ok(error_envelope(
                trace_id,
                request_id,
                "UPSTREAM_TIMEOUT",
                format!("Tool call timed out after {}ms", self.state.tool_timeout_ms),
                true,
            )),
            Ok(Err(UpstreamCallError::Upstream(err))) => Ok(error_envelope(
                trace_id,
                request_id,
                "UPSTREAM_ERROR",
                err,
                false,
            )),
            Err(_) => Ok(error_envelope(
                trace_id,
                request_id,
                "INTERNAL_ERROR",
                "Daemon actor task died",
                true,
            )),
        }
    }

    async fn list_resources_value(&self) -> std::result::Result<Value, String> {
        let mut resources = self
            .state
            .resources
            .iter()
            .map(|(id, meta)| {
                json!({
                    "id": id,
                    "server": meta.server,
                    "uri": meta.uri,
                    "name": meta.name,
                    "description": meta.description,
                    "mime_type": meta.mime_type,
                    "tags": meta.tags,
                })
            })
            .collect::<Vec<_>>();
        let mut server_readiness = self
            .state
            .server_readiness
            .iter()
            .map(|(server, readiness)| {
                json!({
                    "server": server,
                    "code": readiness.code,
                    "message": readiness.message,
                    "retryable": readiness.retryable,
                })
            })
            .collect::<Vec<_>>();

        resources.sort_by(|a, b| {
            a.get("id")
                .and_then(|v| v.as_str())
                .cmp(&b.get("id").and_then(|v| v.as_str()))
        });
        server_readiness.sort_by(|a, b| {
            a.get("server")
                .and_then(|v| v.as_str())
                .cmp(&b.get("server").and_then(|v| v.as_str()))
        });

        Ok(json!({
            "version": "v1",
            "resources": resources,
            "server_readiness": server_readiness,
        }))
    }

    async fn read_resource_value(
        &self,
        resource_id: String,
        request_id: Option<String>,
    ) -> std::result::Result<Value, String> {
        let trace_id = next_trace_id();
        if !self.state.policy.allows(&resource_id) {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "INVALID_ARGS",
                format!("Resource '{}' blocked by policy", resource_id),
                false,
            ));
        }

        let Some(meta) = self.state.resources.get(&resource_id) else {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "RESOURCE_NOT_FOUND",
                format!("Resource '{}' not found", resource_id),
                false,
            ));
        };

        let Some(tx) = self.state.servers.get(&meta.server) else {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "SERVER_UNREACHABLE",
                format!("Server '{}' is unreachable", meta.server),
                true,
            ));
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if tx
            .send(ServerMsg::ReadResource {
                uri: meta.uri.clone(),
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "SERVER_UNREACHABLE",
                format!("Server '{}' mailbox is closed", meta.server),
                true,
            ));
        }

        match reply_rx.await {
            Ok(Ok(data)) => Ok(json!({
                "ok": true,
                "request_id": request_id,
                "trace_id": trace_id,
                "data": data,
                "error": null,
            })),
            Ok(Err(UpstreamCallError::Timeout)) => Ok(error_envelope(
                trace_id,
                request_id,
                "UPSTREAM_TIMEOUT",
                format!(
                    "Resource read timed out after {}ms",
                    self.state.tool_timeout_ms
                ),
                true,
            )),
            Ok(Err(UpstreamCallError::Upstream(err))) => Ok(error_envelope(
                trace_id,
                request_id,
                "UPSTREAM_ERROR",
                err,
                false,
            )),
            Err(_) => Ok(error_envelope(
                trace_id,
                request_id,
                "INTERNAL_ERROR",
                "Daemon actor task died",
                true,
            )),
        }
    }

    async fn list_prompts_value(&self) -> std::result::Result<Value, String> {
        let mut prompts = self
            .state
            .prompts
            .iter()
            .map(|(id, meta)| {
                json!({
                    "id": id,
                    "server": meta.server,
                    "name": meta.name,
                    "title": meta.title,
                    "description": meta.description,
                    "arguments": meta.arguments,
                    "tags": meta.tags,
                })
            })
            .collect::<Vec<_>>();
        let mut server_readiness = self
            .state
            .server_readiness
            .iter()
            .map(|(server, readiness)| {
                json!({
                    "server": server,
                    "code": readiness.code,
                    "message": readiness.message,
                    "retryable": readiness.retryable,
                })
            })
            .collect::<Vec<_>>();

        prompts.sort_by(|a, b| {
            a.get("id")
                .and_then(|v| v.as_str())
                .cmp(&b.get("id").and_then(|v| v.as_str()))
        });
        server_readiness.sort_by(|a, b| {
            a.get("server")
                .and_then(|v| v.as_str())
                .cmp(&b.get("server").and_then(|v| v.as_str()))
        });

        Ok(json!({
            "version": "v1",
            "prompts": prompts,
            "server_readiness": server_readiness,
        }))
    }

    async fn get_prompt_value(
        &self,
        prompt_id: String,
        arguments: Option<Value>,
        request_id: Option<String>,
    ) -> std::result::Result<Value, String> {
        let trace_id = next_trace_id();
        if !self.state.policy.allows(&prompt_id) {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "INVALID_ARGS",
                format!("Prompt '{}' blocked by policy", prompt_id),
                false,
            ));
        }

        let Some(meta) = self.state.prompts.get(&prompt_id) else {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "PROMPT_NOT_FOUND",
                format!("Prompt '{}' not found", prompt_id),
                false,
            ));
        };

        let arguments = match arguments {
            Some(Value::Object(map)) => Some(map),
            Some(_) => {
                return Ok(error_envelope(
                    trace_id,
                    request_id,
                    "INVALID_ARGS",
                    "'arguments' must be a JSON object when provided",
                    false,
                ));
            }
            None => None,
        };

        let Some(tx) = self.state.servers.get(&meta.server) else {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "SERVER_UNREACHABLE",
                format!("Server '{}' is unreachable", meta.server),
                true,
            ));
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if tx
            .send(ServerMsg::GetPrompt {
                name: meta.name.clone(),
                arguments,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return Ok(error_envelope(
                trace_id,
                request_id,
                "SERVER_UNREACHABLE",
                format!("Server '{}' mailbox is closed", meta.server),
                true,
            ));
        }

        match reply_rx.await {
            Ok(Ok(data)) => Ok(json!({
                "ok": true,
                "request_id": request_id,
                "trace_id": trace_id,
                "data": data,
                "error": null,
            })),
            Ok(Err(UpstreamCallError::Timeout)) => Ok(error_envelope(
                trace_id,
                request_id,
                "UPSTREAM_TIMEOUT",
                format!(
                    "Prompt get timed out after {}ms",
                    self.state.tool_timeout_ms
                ),
                true,
            )),
            Ok(Err(UpstreamCallError::Upstream(err))) => Ok(error_envelope(
                trace_id,
                request_id,
                "UPSTREAM_ERROR",
                err,
                false,
            )),
            Err(_) => Ok(error_envelope(
                trace_id,
                request_id,
                "INTERNAL_ERROR",
                "Daemon actor task died",
                true,
            )),
        }
    }
}

fn invalid_args(message: impl Into<String>) -> Value {
    error_envelope(next_trace_id(), None, "INVALID_ARGS", message.into(), false)
}

fn facade_tools() -> Vec<Tool> {
    vec![
        Tool::new(
            TOOL_CAPABILITIES_LIST,
            "START HERE - list available capabilities across every provider; pass server and query to narrow results, and call this first when the exact capability id is unknown",
            schema_object(json!({
                "type":"object",
                "properties":{
                    "server":{"type":"string"},
                    "query":{"type":"string"},
                    "limit":{"type":"integer","minimum":1,"maximum":100}
                },
                "additionalProperties":false
            })),
        ),
        Tool::new(
            TOOL_CAPABILITY_FIND,
            "Find the best capability matches inside one provider for a task; use this instead of broad discovery when the provider is known but the exact capability id is not",
            schema_object(json!({
                "type":"object",
                "properties":{
                    "server":{"type":"string"},
                    "query":{"type":"string"},
                    "limit":{"type":"integer","minimum":1,"maximum":20}
                },
                "required":["server","query"],
                "additionalProperties":false
            })),
        ),
        Tool::new(
            TOOL_CAPABILITY_DESCRIBE,
            "Fetch full schema and examples for one capability id; only use this when capabilities_list summary is not enough to build args",
            schema_object(json!({
                "type":"object",
                "properties":{"id":{"type":"string"}},
                "required":["id"],
                "additionalProperties":false
            })),
        ),
        Tool::new(
            TOOL_CAPABILITY_CALL,
            "Invoke a provider capability directly by id with args; skip capability_describe once the capability id and required args are already known",
            schema_object(json!({
                "type":"object",
                "properties":{
                    "capability_id":{"type":"string"},
                    "args":{"type":"object"},
                    "request_id":{"type":"string"}
                },
                "required":["capability_id","args"],
                "additionalProperties":false
            })),
        ),
        Tool::new(
            TOOL_RESOURCES_LIST,
            "List available resources across providers; use this first to find a resource id before resource_read",
            schema_object(json!({"type":"object","properties":{},"additionalProperties":false})),
        ),
        Tool::new(
            TOOL_RESOURCE_READ,
            "Read one resource by resource_id from resources_list; call this directly once the resource id is known",
            schema_object(json!({
                "type":"object",
                "properties":{
                    "resource_id":{"type":"string"},
                    "request_id":{"type":"string"}
                },
                "required":["resource_id"],
                "additionalProperties":false
            })),
        ),
        Tool::new(
            TOOL_PROMPTS_LIST,
            "List available prompts across providers; use this first to find a prompt id before prompt_get",
            schema_object(json!({"type":"object","properties":{},"additionalProperties":false})),
        ),
        Tool::new(
            TOOL_PROMPT_GET,
            "Render one prompt by prompt_id from prompts_list with optional arguments; call this directly once the prompt id and arg shape are known",
            schema_object(json!({
                "type":"object",
                "properties":{
                    "prompt_id":{"type":"string"},
                    "arguments":{"type":"object"},
                    "request_id":{"type":"string"}
                },
                "required":["prompt_id"],
                "additionalProperties":false
            })),
        ),
    ]
}

fn schema_object(value: Value) -> Arc<Map<String, Value>> {
    Arc::new(value.as_object().cloned().unwrap_or_default())
}

fn next_trace_id() -> String {
    format!("trace-{}", TRACE_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn error_envelope(
    trace_id: String,
    request_id: Option<String>,
    code: &str,
    message: impl Into<String>,
    retryable: bool,
) -> Value {
    json!({
        "ok": false,
        "request_id": request_id,
        "trace_id": trace_id,
        "data": null,
        "error": {
            "code": code,
            "message": message.into(),
            "retryable": retryable,
        }
    })
}

pub async fn run_mcp_server(config: McpConfig) -> Result<()> {
    let state = initialize_state(config).await?;
    let server = FacadeMcpServer { state };
    let running = server.serve(stdio()).await?;
    let _ = running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{facade_tools, invalid_args, FacadeMcpServer};
    use crate::daemon::{AppState, CapabilityMeta, Policy};
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn facade_tools_include_all_lightweight_operations() {
        let names = facade_tools()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 8);
        assert!(names.contains(&"capabilities_list".to_string()));
        assert!(names.contains(&"capability_find".to_string()));
        assert!(names.contains(&"capability_describe".to_string()));
        assert!(names.contains(&"capability_call".to_string()));
        assert!(names.contains(&"resources_list".to_string()));
        assert!(names.contains(&"resource_read".to_string()));
        assert!(names.contains(&"prompts_list".to_string()));
        assert!(names.contains(&"prompt_get".to_string()));
    }

    #[test]
    fn invalid_args_envelope_has_expected_shape() {
        let payload = invalid_args("bad input");
        assert_eq!(payload["ok"], false);
        assert_eq!(payload["error"]["code"], "INVALID_ARGS");
        assert_eq!(payload["error"]["message"], "bad input");
        assert_eq!(payload["data"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn capability_list_supports_server_query_and_limit_filters() {
        let mut capabilities = HashMap::new();
        capabilities.insert(
            "figma.whoami".to_string(),
            CapabilityMeta {
                server: "figma".to_string(),
                tool: "whoami".to_string(),
                summary: "Get the authenticated Figma user".to_string(),
                description: "desc".to_string(),
                input_schema: serde_json::json!({}),
                tags: vec!["figma".to_string()],
                examples: vec![],
            },
        );
        capabilities.insert(
            "notion.notion-search".to_string(),
            CapabilityMeta {
                server: "notion".to_string(),
                tool: "notion-search".to_string(),
                summary: "Search notion users and pages".to_string(),
                description: "desc".to_string(),
                input_schema: serde_json::json!({}),
                tags: vec!["notion".to_string()],
                examples: vec![],
            },
        );
        capabilities.insert(
            "notion.fetch".to_string(),
            CapabilityMeta {
                server: "notion".to_string(),
                tool: "fetch".to_string(),
                summary: "Fetch a notion page".to_string(),
                description: "desc".to_string(),
                input_schema: serde_json::json!({}),
                tags: vec!["notion".to_string()],
                examples: vec![],
            },
        );

        let server = FacadeMcpServer {
            state: AppState {
                servers: Arc::new(HashMap::new()),
                server_readiness: Arc::new(HashMap::new()),
                capabilities: Arc::new(capabilities),
                resources: Arc::new(HashMap::new()),
                prompts: Arc::new(HashMap::new()),
                tool_timeout_ms: 30_000,
                policy: Policy::from_config(None),
            },
        };

        let value = server
            .list_capabilities_value(
                Some("notion".to_string()),
                Some("search".to_string()),
                Some(1),
            )
            .await
            .expect("capability list should succeed");
        let capabilities = value["capabilities"]
            .as_array()
            .expect("capabilities array should exist");

        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0]["id"], "notion.notion-search");
    }

    #[tokio::test]
    async fn capability_find_returns_ranked_matches_with_arg_hints() {
        let mut capabilities = HashMap::new();
        capabilities.insert(
            "linear.list_issues".to_string(),
            CapabilityMeta {
                server: "linear".to_string(),
                tool: "list_issues".to_string(),
                summary: "List issues with filters like assignee and state".to_string(),
                description: "desc".to_string(),
                input_schema: serde_json::json!({
                    "type":"object",
                    "properties":{
                        "assignee":{"type":"string"},
                        "state":{"type":"string"},
                        "limit":{"type":"integer"}
                    },
                    "required":["assignee"]
                }),
                tags: vec!["linear".to_string()],
                examples: vec![],
            },
        );
        capabilities.insert(
            "linear.list_users".to_string(),
            CapabilityMeta {
                server: "linear".to_string(),
                tool: "list_users".to_string(),
                summary: "List users".to_string(),
                description: "desc".to_string(),
                input_schema: serde_json::json!({"type":"object","properties":{}}),
                tags: vec!["linear".to_string()],
                examples: vec![],
            },
        );

        let server = FacadeMcpServer {
            state: AppState {
                servers: Arc::new(HashMap::new()),
                server_readiness: Arc::new(HashMap::new()),
                capabilities: Arc::new(capabilities),
                resources: Arc::new(HashMap::new()),
                prompts: Arc::new(HashMap::new()),
                tool_timeout_ms: 30_000,
                policy: Policy::from_config(None),
            },
        };

        let value = server
            .find_capability_value(
                "linear".to_string(),
                "my in progress issues".to_string(),
                Some(3),
            )
            .await
            .expect("capability find should succeed");
        let matches = value["matches"].as_array().expect("matches array should exist");

        assert_eq!(matches[0]["id"], "linear.list_issues");
        assert_eq!(matches[0]["required_fields"][0], "assignee");
    }
}
