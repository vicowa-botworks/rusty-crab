//! Replays the wire-type fixtures against this crate.
//!
//! The fixture's `value` is a *description* of the Go value, not wire JSON:
//! `json.Marshal` drops both `nil` and `[]` for an `omitempty` slice, so the wire
//! form could not say which of the two a case was testing. `null` and `[]` stay
//! distinguishable here, and this file is where they get mapped onto the Rust
//! types' own nil/empty split.
//!
//! Escaping is deliberately thin here: each of the three HTML escapes is pinned
//! by exactly two cases, and U+2028/U+2029 only rides along in the fuzz alphabet.
//! That is not a gap to widen -- `go_json_encode_parameters.json` owns escaping
//! and pins it exhaustively at the encoder that implements it. What this crate
//! has to prove is that a wire type routes its strings through that encoder, so
//! two cases per escape is the right amount of evidence.

use std::collections::BTreeMap;

use conformance::{go_value::to_go_value, Fixture, Report};
use crab_gojson::Value;
use crab_protocoltypes::{
    Attachment, CacheControl, ContentBlock, ExtraContent, FunctionCall, GoTime, GoogleExtra,
    LLMResponse, Message, ReasoningDetail, StreamChunk, ToolCall, ToolDefinition,
    ToolFunctionDefinition, UsageInfo,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value as Json;

#[test]
fn marshal_matches_go_json() {
    let fixture = Fixture::load("protocoltypes_marshal.json");
    let mut report = Report::new(&fixture);

    for case in &fixture.cases {
        let input: FixtureWire = case.parse();
        let got = match input.kind.as_str() {
            "message" => marshal_one::<FixtureMessage, Message>(&input.value, Message::from),
            "llm_response" => {
                marshal_one::<FixtureLLMResponse, LLMResponse>(&input.value, LLMResponse::from)
            }
            "tool_definition" => marshal_one::<FixtureToolDefinition, ToolDefinition>(
                &input.value,
                ToolDefinition::from,
            ),
            "stream_chunk" => {
                marshal_one::<FixtureStreamChunk, StreamChunk>(&input.value, StreamChunk::from)
            }
            "content_block" => {
                marshal_one::<FixtureContentBlock, ContentBlock>(&input.value, ContentBlock::from)
            }
            "attachment" => {
                marshal_one::<FixtureAttachment, Attachment>(&input.value, Attachment::from)
            }
            "reasoning_detail" => marshal_one::<FixtureReasoningDetail, ReasoningDetail>(
                &input.value,
                ReasoningDetail::from,
            ),
            other => panic!("case {}: unknown kind {other:?}", case.name),
        };
        report.record(case, got);
    }

    report.finish(12);
}

/// Marshals one value, reporting Go's `null` for the (here unreachable) case of a
/// value Go would refuse, so a failure is a byte difference and not a panic.
fn marshal_one<T, U>(value: &RawValue, convert: impl FnOnce(T) -> U) -> Json
where
    for<'de> T: Deserialize<'de>,
    U: crab_gojson::GoMarshal,
{
    let typed: T = serde_json::from_str(value.get())
        .unwrap_or_else(|e| panic!("value does not match the described shape: {e}"));
    match crab_protocoltypes::marshal(&convert(typed)) {
        Ok(bytes) => Json::String(String::from_utf8_lossy(&bytes).to_string()),
        Err(_) => Json::Null,
    }
}

// ------------------------------------------------------------------ envelope --

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureWire {
    kind: String,
    /// Kept as text so a number like `-0` survives into the typed value.
    value: Box<serde_json::value::RawValue>,
}

// -------------------------------------------------------------------- message --

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureMessage {
    role: String,
    content: String,
    model_name: String,
    created_at: Option<FixtureTime>,
    media: Option<Vec<String>>,
    attachments: Option<Vec<FixtureAttachment>>,
    reasoning_content: String,
    system_parts: Option<Vec<FixtureContentBlock>>,
    tool_calls: Option<Vec<FixtureToolCall>>,
    tool_call_id: String,
    prompt_layer: String,
    prompt_slot: String,
    prompt_source: String,
}

impl From<FixtureMessage> for Message {
    fn from(f: FixtureMessage) -> Message {
        Message {
            role: f.role,
            content: f.content,
            model_name: f.model_name,
            created_at: f.created_at.map(GoTime::from),
            media: f.media,
            attachments: f
                .attachments
                .map(|v| v.into_iter().map(Attachment::from).collect()),
            reasoning_content: f.reasoning_content,
            system_parts: f
                .system_parts
                .map(|v| v.into_iter().map(ContentBlock::from).collect()),
            tool_calls: f
                .tool_calls
                .map(|v| v.into_iter().map(ToolCall::from).collect()),
            tool_call_id: f.tool_call_id,
            prompt_layer: f.prompt_layer,
            prompt_slot: f.prompt_slot,
            prompt_source: f.prompt_source,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTime {
    unix_seconds: i64,
    nanos: u32,
    offset_seconds: i32,
}

impl From<FixtureTime> for GoTime {
    fn from(f: FixtureTime) -> GoTime {
        GoTime {
            unix_seconds: f.unix_seconds,
            nanos: f.nanos,
            offset_seconds: f.offset_seconds,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    arguments: Option<Json>,
    name: String,
    thought_signature: String,
    function: Option<FixtureFunctionCall>,
    extra_content: Option<FixtureExtraContent>,
}

impl From<FixtureToolCall> for ToolCall {
    fn from(f: FixtureToolCall) -> ToolCall {
        ToolCall {
            id: f.id,
            call_type: f.call_type,
            function: f.function.map(FunctionCall::from),
            name: f.name,
            arguments: f.arguments.map(go_map),
            thought_signature: f.thought_signature,
            extra_content: f.extra_content.map(ExtraContent::from),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFunctionCall {
    name: String,
    arguments: String,
    thought_signature: String,
}

impl From<FixtureFunctionCall> for FunctionCall {
    fn from(f: FixtureFunctionCall) -> FunctionCall {
        FunctionCall {
            name: f.name,
            arguments: f.arguments,
            thought_signature: f.thought_signature,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureExtraContent {
    google: Option<FixtureGoogleExtra>,
    tool_feedback_explanation: String,
}

impl From<FixtureExtraContent> for ExtraContent {
    fn from(f: FixtureExtraContent) -> ExtraContent {
        ExtraContent {
            google: f.google.map(GoogleExtra::from),
            tool_feedback_explanation: f.tool_feedback_explanation,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureGoogleExtra {
    thought_signature: String,
}

impl From<FixtureGoogleExtra> for GoogleExtra {
    fn from(f: FixtureGoogleExtra) -> GoogleExtra {
        GoogleExtra {
            thought_signature: f.thought_signature,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: String,
    cache_control: Option<FixtureCacheControl>,
    prompt_layer: String,
    prompt_slot: String,
    prompt_source: String,
}

impl From<FixtureContentBlock> for ContentBlock {
    fn from(f: FixtureContentBlock) -> ContentBlock {
        ContentBlock {
            block_type: f.block_type,
            text: f.text,
            cache_control: f.cache_control.map(CacheControl::from),
            prompt_layer: f.prompt_layer,
            prompt_slot: f.prompt_slot,
            prompt_source: f.prompt_source,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCacheControl {
    #[serde(rename = "type")]
    control_type: String,
}

impl From<FixtureCacheControl> for CacheControl {
    fn from(f: FixtureCacheControl) -> CacheControl {
        CacheControl {
            control_type: f.control_type,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureAttachment {
    #[serde(rename = "type")]
    attachment_type: String,
    #[serde(rename = "ref")]
    ref_: String,
    url: String,
    filename: String,
    content_type: String,
}

impl From<FixtureAttachment> for Attachment {
    fn from(f: FixtureAttachment) -> Attachment {
        Attachment {
            attachment_type: f.attachment_type,
            ref_: f.ref_,
            url: f.url,
            filename: f.filename,
            content_type: f.content_type,
        }
    }
}

// ------------------------------------------------------------- other kinds --

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureLLMResponse {
    content: String,
    reasoning_content: String,
    tool_calls: Option<Vec<FixtureToolCall>>,
    finish_reason: String,
    usage: Option<FixtureUsage>,
    reasoning: String,
    reasoning_details: Option<Vec<FixtureReasoningDetail>>,
}

impl From<FixtureLLMResponse> for LLMResponse {
    fn from(f: FixtureLLMResponse) -> LLMResponse {
        LLMResponse {
            content: f.content,
            reasoning_content: f.reasoning_content,
            tool_calls: f
                .tool_calls
                .map(|v| v.into_iter().map(ToolCall::from).collect()),
            finish_reason: f.finish_reason,
            usage: f.usage.map(UsageInfo::from),
            reasoning: f.reasoning,
            reasoning_details: f
                .reasoning_details
                .map(|v| v.into_iter().map(ReasoningDetail::from).collect()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureUsage {
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
}

impl From<FixtureUsage> for UsageInfo {
    fn from(f: FixtureUsage) -> UsageInfo {
        UsageInfo {
            prompt_tokens: f.prompt_tokens,
            completion_tokens: f.completion_tokens,
            total_tokens: f.total_tokens,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureReasoningDetail {
    format: String,
    index: i64,
    #[serde(rename = "type")]
    detail_type: String,
    text: String,
}

impl From<FixtureReasoningDetail> for ReasoningDetail {
    fn from(f: FixtureReasoningDetail) -> ReasoningDetail {
        ReasoningDetail {
            format: f.format,
            index: f.index,
            detail_type: f.detail_type,
            text: f.text,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureToolDefinition {
    #[serde(rename = "type")]
    def_type: String,
    function: FixtureToolFunction,
    prompt_layer: String,
    prompt_slot: String,
    prompt_source: String,
}

impl From<FixtureToolDefinition> for ToolDefinition {
    fn from(f: FixtureToolDefinition) -> ToolDefinition {
        ToolDefinition {
            def_type: f.def_type,
            function: ToolFunctionDefinition {
                name: f.function.name,
                description: f.function.description,
                parameters: f.function.parameters.map(go_map),
            },
            prompt_layer: f.prompt_layer,
            prompt_slot: f.prompt_slot,
            prompt_source: f.prompt_source,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureToolFunction {
    name: String,
    description: String,
    parameters: Option<Json>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureStreamChunk {
    #[serde(rename = "Content")]
    content: String,
    #[serde(rename = "ReasoningContent")]
    reasoning_content: String,
}

impl From<FixtureStreamChunk> for StreamChunk {
    fn from(f: FixtureStreamChunk) -> StreamChunk {
        StreamChunk {
            content: f.content,
            reasoning_content: f.reasoning_content,
        }
    }
}

/// The described value for a Go `map[string]any`. A non-object here would mean
/// the generator described something the field cannot hold, so this fails rather
/// than coercing.
fn go_map(v: Json) -> BTreeMap<String, Value> {
    match v {
        Json::Object(map) => map
            .into_iter()
            .map(|(k, val)| (k, to_go_value(&val)))
            .collect(),
        other => panic!("a Go map[string]any cannot hold {other}"),
    }
}
