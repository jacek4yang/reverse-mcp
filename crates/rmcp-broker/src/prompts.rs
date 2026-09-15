//! #20 MCP prompts: workflow hints that teach agents to prefer high-level
//! workflows before issuing long chains of atomic tool calls.

use rmcp::model::{
    GetPromptRequestParams, GetPromptResult, ListPromptsResult, Prompt, PromptArgument,
    PromptMessage, Role,
};

/// The prompt catalog (issue #20 scope).
pub fn list() -> ListPromptsResult {
    let arg = |name: &str, desc: &str, required: bool| {
        let mut a = PromptArgument::new(name);
        a.description = Some(desc.to_string());
        a.required = Some(required);
        a
    };
    let prompts = vec![
        Prompt::new(
            "ida_survey_binary",
            Some(
                "Survey a binary end to end: metadata, segments, entry points, imports, functions overview, and notable strings — then report structure and attack/analysis surface.",
            ),
            Some(vec![arg(
                "db",
                "db handle (db1, db2, ...); omit when exactly one DB is open",
                false,
            )]),
        ),
        Prompt::new(
            "ida_analyze_function_deep",
            Some(
                "Deep-dive one function: decompile, list lvars, inspect callees and xrefs, check strings/constants, and summarize behavior with evidence.",
            ),
            Some(vec![
                arg(
                    "ea",
                    "address inside the target function (hex 0x.. or decimal)",
                    true,
                ),
                arg("db", "db handle; omit when exactly one DB is open", false),
            ]),
        ),
        Prompt::new(
            "ida_trace_data_flow",
            Some(
                "Trace data flow from a source (argument, import, string) to sinks: follow xrefs both directions, decompile along the path, and report the chain with evidence.",
            ),
            Some(vec![
                arg("ea", "start address for the flow", true),
                arg("db", "db handle; omit when exactly one DB is open", false),
            ]),
        ),
        Prompt::new(
            "ida_safe_refactor",
            Some(
                "Safe rename/retype/refactor workflow: plan mutations, review the preview, apply with expected_revision, verify via audit — never bulk-patch without a snapshot.",
            ),
            Some(vec![arg(
                "db",
                "db handle; omit when exactly one DB is open",
                false,
            )]),
        ),
        Prompt::new(
            "ida_compare_binaries",
            Some(
                "Compare two databases: open both, diff function counts/segments/strings/names, and report likely shared or divergent code regions.",
            ),
            Some(vec![
                arg("db1", "first db handle", true),
                arg("db2", "second db handle", true),
            ]),
        ),
    ];
    ListPromptsResult::with_all_items(prompts)
}

/// Render one prompt as an instruction message for the agent.
pub fn get(request: &GetPromptRequestParams) -> Result<GetPromptResult, rmcp::ErrorData> {
    let args = request.arguments.clone().unwrap_or_default();
    let db = args
        .get("db")
        .and_then(|v| v.as_str())
        .unwrap_or("the single open db handle (omit the db argument when only one DB is open)");
    let ea = args.get("ea").and_then(|v| v.as_str()).unwrap_or("<ea>");
    let db1 = args.get("db1").and_then(|v| v.as_str()).unwrap_or("<db1>");
    let db2 = args.get("db2").and_then(|v| v.as_str()).unwrap_or("<db2>");

    let text = match request.name.as_ref() {
        "ida_survey_binary" => format!(
            "Survey the binary at {db}.\n\
             1. Read the ida://db/{db}/metadata and ida://db/{db}/segments resources.\n\
             2. Read ida://db/{db}/imports and ida://db/{db}/entrypoints for the API and start surface.\n\
             3. Call ida_functions (limit ~100) for the layout; call ida_search for interesting strings/constants.\n\
             4. Summarize: binary type, language/runtime clues, protection, notable functionality, and which functions deserve deep analysis first.\n\
             Prefer resources and batched reads over many small tool calls; report evidence (addresses, names), not conclusions without them."
        ),
        "ida_analyze_function_deep" => format!(
            "Deep-dive the function containing {ea} in {db}.\n\
             1. ida_inspect the address, then ida_decompile it.\n\
             2. Use ida_hr action=cfunc for lvars/types when decompile is noisy.\n\
             3. ida_xrefs (to and from) on the entry; decompile the most relevant callees once each.\n\
             4. ida_search for constants/strings used inside it.\n\
             5. Summarize behavior with an evidence table: address -> fact.\n\
             Batch independent reads with ida_batch where possible."
        ),
        "ida_trace_data_flow" => format!(
            "Trace data flow starting at {ea} in {db}.\n\
             1. ida_xrefs direction=to to find who feeds this address; follow upward while the path stays interesting.\n\
             2. ida_xrefs direction=from to find where the data goes (sinks: calls, memory writes).\n\
             3. Decompile each hop once; record the value's transformation at each step.\n\
             4. Report the chain as source -> transforms -> sink with addresses; flag where the trail needs runtime evidence."
        ),
        "ida_safe_refactor" => format!(
            "Refactor safely in {db}.\n\
             1. Write the change set as operations for ida_mutation action=plan (rename/comment/patch_bytes/func.*).\n\
             2. Review the preview rows; fix anything with target_resolves=false.\n\
             3. For byte changes, take ida_mutation action=snapshot first.\n\
             4. ida_mutation action=apply with expected_revision = current revision.\n\
             5. ida_mutation action=audit to verify every change; on failure inspect partial results and re-plan.\n\
             Never bulk-patch without a snapshot; never skip expected_revision."
        ),
        "ida_compare_binaries" => format!(
            "Compare {db1} and {db2}.\n\
             1. ida_db action=info on both (read resources ida://db/{db1}/info and ida://db/{db2}/info).\n\
             2. Compare function counts, segments (ida_segments on both), and strings via ida_search.\n\
             3. Sample shared-looking functions with ida_decompile on each side; compare hashes via ida_metadata (md5/sha256 of inputs).\n\
             4. Report shared regions, divergences, and confidence based on evidence counts."
        ),
        other => {
            return Err(rmcp::ErrorData::invalid_params(
                format!("[invalid_args] unknown prompt '{other}'"),
                None,
            ));
        }
    };

    Ok(
        GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)])
            .with_description("reverse-mcp workflow hint"),
    )
}
