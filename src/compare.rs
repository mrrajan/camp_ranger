use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;

#[derive(Debug, Clone)]
pub struct NormalizedNode {
    pub normalized_node_id: String,
    pub name: String,
    pub version: String,
    pub purl: Vec<String>,
    pub cpe: Vec<String>,
    pub published: String,
    pub relationship: Option<String>,
    pub depth: usize,
    pub sbom_id: Option<String>,
    pub document_id: Option<String>,
    pub warnings: Vec<String>,
    pub parent_normalized_id: Option<String>,
    pub children_normalized_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FieldMismatch {
    pub node_id: String,
    pub field_name: String,
    pub api_value: String,
    pub tool_value: String,
}

#[derive(Debug, Serialize)]
pub struct StructuralMismatch {
    pub node_id: String,
    pub mismatch_type: String,
    pub api_value: String,
    pub tool_value: String,
}

#[derive(Debug, Serialize)]
pub struct MissingInToolRecord {
    pub api_node_id: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub cpe: String,
    pub published: String,
    pub relationship: String,
    pub depth_level: usize,
    pub sbom_id: String,
    pub document_id: String,
    pub has_warnings: String,
    pub warnings: String,
    pub node_id_mismatch: String,
    pub tool_node_id: String,
}

#[derive(Debug, Serialize)]
pub struct MissingInApiRecord {
    pub tool_node_id: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub cpe: String,
    pub published: String,
    pub relationship: String,
    pub depth_level: usize,
    pub sbom_id: String,
    pub document_id: String,
    pub has_warnings: String,
    pub warnings: String,
    pub node_id_mismatch: String,
    pub api_node_id: String,
}

pub struct ComparisonResult {
    pub api_node_count: usize,
    pub tool_node_count: usize,
    pub matched_node_count: usize,
    pub missing_in_tool: Vec<NormalizedNode>,
    pub missing_in_api: Vec<NormalizedNode>,
    pub field_mismatches: Vec<FieldMismatch>,
    pub structural_mismatches: Vec<StructuralMismatch>,
    pub node_id_mismatch_tool: HashMap<String, String>,
    pub node_id_mismatch_api: HashMap<String, String>,
}

fn normalize_node_id(node_id: &str) -> String {
    let decoded = urlencoding::decode(node_id)
        .unwrap_or(std::borrow::Cow::Borrowed(node_id))
        .into_owned();
    if decoded.starts_with("pkg:") {
        if let Some(q) = decoded.find('?') {
            return decoded[..q].to_string();
        }
    }
    decoded
}

fn extract_sha256(s: &str) -> Option<&str> {
    let decoded_check = s;
    if let Some(pos) = decoded_check.find("sha256:") {
        let hash_start = pos + 7;
        let hash = &decoded_check[hash_start..];
        let end = hash
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hash.len());
        if end >= 64 {
            return Some(&decoded_check[hash_start..hash_start + 64]);
        }
    }
    None
}

fn normalize_purl(purl: &str) -> String {
    let decoded = urlencoding::decode(purl)
        .unwrap_or(std::borrow::Cow::Borrowed(purl))
        .into_owned();
    if let Some(q) = decoded.find('?') {
        decoded[..q].to_string()
    } else {
        decoded
    }
}

fn normalize_purl_set(purls: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = purls.iter().map(|p| normalize_purl(p)).collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn normalize_timestamp(timestamp: &str) -> String {
    // "2025-12-02 12:05:38+00" -> "2025-12-02T12:05:38Z"
    if timestamp.contains(' ') && timestamp.contains('+') {
        let parts: Vec<&str> = timestamp.split(' ').collect();
        if parts.len() >= 2 {
            let date = parts[0];
            let time_parts: Vec<&str> = parts[1].split('+').collect();
            if !time_parts.is_empty() {
                return format!("{}T{}Z", date, time_parts[0]);
            }
        }
    }
    timestamp.to_string()
}

fn extract_json_string_array(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn flatten_node(
    value: &serde_json::Value,
    depth: usize,
    parent_id: Option<&str>,
    result: &mut HashMap<String, NormalizedNode>,
) {
    let node_id = value["node_id"].as_str().unwrap_or_default();
    if node_id.is_empty() {
        return;
    }
    let normalized_id = normalize_node_id(node_id);

    let descendants = value["descendants"].as_array();
    let ancestors = value["ancestors"].as_array();

    let mut child_ids = Vec::new();
    if let Some(descs) = descendants {
        for d in descs {
            let child_node_id = d["node_id"].as_str().unwrap_or_default();
            if !child_node_id.is_empty() {
                child_ids.push(normalize_node_id(child_node_id));
            }
        }
    }
    if let Some(ancs) = ancestors {
        for a in ancs {
            let anc_node_id = a["node_id"].as_str().unwrap_or_default();
            if !anc_node_id.is_empty() {
                child_ids.push(normalize_node_id(anc_node_id));
            }
        }
    }

    if result.contains_key(&normalized_id) {
        log::debug!("Duplicate normalized_node_id: {}", normalized_id);
    }

    let node = NormalizedNode {
        normalized_node_id: normalized_id.clone(),
        name: value["name"].as_str().unwrap_or_default().to_string(),
        version: value["version"].as_str().unwrap_or_default().to_string(),
        purl: extract_json_string_array(&value["purl"]),
        cpe: extract_json_string_array(&value["cpe"]),
        published: normalize_timestamp(value["published"].as_str().unwrap_or_default()),
        relationship: value["relationship"].as_str().map(|s| s.to_string()),
        depth,
        sbom_id: value["sbom_id"].as_str().map(|s| s.to_string()),
        document_id: value["document_id"].as_str().map(|s| s.to_string()),
        warnings: extract_json_string_array(&value["warnings"]),
        parent_normalized_id: parent_id.map(|s| s.to_string()),
        children_normalized_ids: child_ids,
    };

    result.insert(normalized_id.clone(), node);

    if let Some(descs) = descendants {
        for d in descs {
            flatten_node(d, depth + 1, Some(&normalized_id), result);
        }
    }
    if let Some(ancs) = ancestors {
        for a in ancs {
            flatten_node(a, depth + 1, Some(&normalized_id), result);
        }
    }
}

fn compare_fields(api_node: &NormalizedNode, tool_node: &NormalizedNode) -> Vec<FieldMismatch> {
    let mut mismatches = Vec::new();
    let nid = &api_node.normalized_node_id;

    if api_node.name != tool_node.name {
        mismatches.push(FieldMismatch {
            node_id: nid.clone(),
            field_name: "name".to_string(),
            api_value: api_node.name.clone(),
            tool_value: tool_node.name.clone(),
        });
    }

    if api_node.version != tool_node.version {
        mismatches.push(FieldMismatch {
            node_id: nid.clone(),
            field_name: "version".to_string(),
            api_value: api_node.version.clone(),
            tool_value: tool_node.version.clone(),
        });
    }

    let api_purls = normalize_purl_set(&api_node.purl);
    let tool_purls = normalize_purl_set(&tool_node.purl);
    if api_purls != tool_purls {
        mismatches.push(FieldMismatch {
            node_id: nid.clone(),
            field_name: "purl".to_string(),
            api_value: api_purls.join("; "),
            tool_value: tool_purls.join("; "),
        });
    }

    let mut api_cpe = api_node.cpe.clone();
    api_cpe.sort();
    let mut tool_cpe = tool_node.cpe.clone();
    tool_cpe.sort();
    if api_cpe != tool_cpe {
        mismatches.push(FieldMismatch {
            node_id: nid.clone(),
            field_name: "cpe".to_string(),
            api_value: api_cpe.join("; "),
            tool_value: tool_cpe.join("; "),
        });
    }

    if api_node.relationship != tool_node.relationship {
        mismatches.push(FieldMismatch {
            node_id: nid.clone(),
            field_name: "relationship".to_string(),
            api_value: api_node.relationship.clone().unwrap_or_default(),
            tool_value: tool_node.relationship.clone().unwrap_or_default(),
        });
    }

    mismatches
}

fn compare_structure(
    api_node: &NormalizedNode,
    tool_node: &NormalizedNode,
) -> Vec<StructuralMismatch> {
    let mut mismatches = Vec::new();
    let nid = &api_node.normalized_node_id;

    if api_node.parent_normalized_id != tool_node.parent_normalized_id {
        mismatches.push(StructuralMismatch {
            node_id: nid.clone(),
            mismatch_type: "parent_differs".to_string(),
            api_value: api_node
                .parent_normalized_id
                .clone()
                .unwrap_or_else(|| "(root)".to_string()),
            tool_value: tool_node
                .parent_normalized_id
                .clone()
                .unwrap_or_else(|| "(root)".to_string()),
        });
    }

    let mut api_children = api_node.children_normalized_ids.clone();
    let mut tool_children = tool_node.children_normalized_ids.clone();
    api_children.sort();
    tool_children.sort();
    if api_children != tool_children {
        let api_set: HashSet<_> = api_children.iter().collect();
        let tool_set: HashSet<_> = tool_children.iter().collect();
        let only_api: Vec<_> = api_set.difference(&tool_set).collect();
        let only_tool: Vec<_> = tool_set.difference(&api_set).collect();
        if !only_api.is_empty() || !only_tool.is_empty() {
            mismatches.push(StructuralMismatch {
                node_id: nid.clone(),
                mismatch_type: "children_differ".to_string(),
                api_value: format!(
                    "{} children ({} only in API)",
                    api_children.len(),
                    only_api.len()
                ),
                tool_value: format!(
                    "{} children ({} only in tool)",
                    tool_children.len(),
                    only_tool.len()
                ),
            });
        }
    }

    mismatches
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

pub fn compare_hierarchies(
    api_json: &serde_json::Value,
    tool_json: &serde_json::Value,
) -> Result<ComparisonResult, Box<dyn Error>> {
    let api_items = api_json["items"]
        .as_array()
        .ok_or("API response missing 'items' array")?;
    let tool_items = tool_json["items"]
        .as_array()
        .ok_or("Tool response missing 'items' array")?;

    let mut api_nodes = HashMap::new();
    for item in api_items {
        flatten_node(item, 0, None, &mut api_nodes);
    }

    let mut tool_nodes = HashMap::new();
    for item in tool_items {
        flatten_node(item, 0, None, &mut tool_nodes);
    }

    log::info!("API nodes (flattened): {}", api_nodes.len());
    log::info!("Tool nodes (flattened): {}", tool_nodes.len());

    let api_ids: HashSet<_> = api_nodes.keys().cloned().collect();
    let tool_ids: HashSet<_> = tool_nodes.keys().cloned().collect();
    let matched_ids: HashSet<_> = api_ids.intersection(&tool_ids).cloned().collect();

    let mut missing_in_tool: Vec<_> = api_ids
        .difference(&tool_ids)
        .filter_map(|id| api_nodes.get(id).cloned())
        .collect();
    missing_in_tool.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.name.cmp(&b.name)));

    let mut missing_in_api: Vec<_> = tool_ids
        .difference(&api_ids)
        .filter_map(|id| tool_nodes.get(id).cloned())
        .collect();
    missing_in_api.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.name.cmp(&b.name)));

    // Detect node_id mismatches: unmatched API nodes that have a corresponding tool node
    // with the same SHA256 digest but a different node_id.
    // First checks missing_in_api (same depth), then falls back to all tool nodes (any depth)
    // to catch cases where flatten deduplication dropped the tool's counterpart.
    let mut node_id_mismatch_map: HashMap<String, String> = HashMap::new();
    for api_node in &missing_in_tool {
        let api_hash = extract_sha256(&api_node.normalized_node_id)
            .or_else(|| api_node.purl.iter().find_map(|p| extract_sha256(p)));
        if let Some(api_hash) = api_hash {
            // First: try matching against missing_in_api at the same depth
            let found = missing_in_api.iter().find(|tool_node| {
                tool_node.depth == api_node.depth && {
                    let tool_hash = extract_sha256(&tool_node.normalized_node_id)
                        .or_else(|| tool_node.purl.iter().find_map(|p| extract_sha256(p)));
                    tool_hash == Some(api_hash)
                }
            });
            if let Some(tool_node) = found {
                node_id_mismatch_map.insert(
                    api_node.normalized_node_id.clone(),
                    tool_node.normalized_node_id.clone(),
                );
                continue;
            }
            // Fallback: search all tool nodes for a SHA256 match at any depth.
            // Handles cases where the tool's counterpart was deduplicated by flatten
            // (e.g. same component name at depth 2 and 4, depth 4 overwrites depth 2).
            let found_any = tool_nodes.values().find(|tool_node| {
                tool_node.normalized_node_id != api_node.normalized_node_id && {
                    let tool_hash = extract_sha256(&tool_node.normalized_node_id)
                        .or_else(|| tool_node.purl.iter().find_map(|p| extract_sha256(p)));
                    tool_hash == Some(api_hash)
                }
            });
            if let Some(tool_node) = found_any {
                node_id_mismatch_map.insert(
                    api_node.normalized_node_id.clone(),
                    tool_node.normalized_node_id.clone(),
                );
            }
        }
    }
    if !node_id_mismatch_map.is_empty() {
        log::info!(
            "Detected {} node_id mismatches in missing_in_tool (same SHA256, different node_id)",
            node_id_mismatch_map.len()
        );
    }

    // Reverse direction: detect tool nodes in missing_in_api that have an API counterpart.
    // First, SHA256 scan (same as above but reversed).
    let mut node_id_mismatch_api: HashMap<String, String> = HashMap::new();
    for tool_node in &missing_in_api {
        let tool_hash = extract_sha256(&tool_node.normalized_node_id)
            .or_else(|| tool_node.purl.iter().find_map(|p| extract_sha256(p)));
        if let Some(tool_hash) = tool_hash {
            let found = missing_in_tool.iter().find(|api_node| {
                api_node.depth == tool_node.depth && {
                    let api_hash = extract_sha256(&api_node.normalized_node_id)
                        .or_else(|| api_node.purl.iter().find_map(|p| extract_sha256(p)));
                    api_hash == Some(tool_hash)
                }
            });
            if let Some(api_node) = found {
                node_id_mismatch_api.insert(
                    tool_node.normalized_node_id.clone(),
                    api_node.normalized_node_id.clone(),
                );
                continue;
            }
            let found_any = api_nodes.values().find(|api_node| {
                api_node.normalized_node_id != tool_node.normalized_node_id && {
                    let api_hash = extract_sha256(&api_node.normalized_node_id)
                        .or_else(|| api_node.purl.iter().find_map(|p| extract_sha256(p)));
                    api_hash == Some(tool_hash)
                }
            });
            if let Some(api_node) = found_any {
                node_id_mismatch_api.insert(
                    tool_node.normalized_node_id.clone(),
                    api_node.normalized_node_id.clone(),
                );
            }
        }
    }
    // Second pass: reverse the forward map to catch cases lost to flatten deduplication.
    // If missing_in_tool already says "API node X <-> tool node Y", then tool node Y
    // in missing_in_api should also be flagged pointing back to API node X.
    let missing_in_api_ids: HashSet<_> = missing_in_api
        .iter()
        .map(|n| n.normalized_node_id.clone())
        .collect();
    for (api_id, tool_id) in &node_id_mismatch_map {
        if missing_in_api_ids.contains(tool_id) && !node_id_mismatch_api.contains_key(tool_id) {
            node_id_mismatch_api.insert(tool_id.clone(), api_id.clone());
        }
    }
    // Third pass: for still-unmatched tool nodes, check if the forward map has an entry
    // for the SAME API node_id but pointing to a DIFFERENT tool node (same component,
    // different release). This handles flatten dedup where the API has duplicate node_ids
    // across releases — only one purl survives, so the forward map only captures one pair,
    // but the other release's tool node shares the same name and depth.
    // When the API node_id contains an arch suffix (e.g. _amd64, _arm64), prefer matching
    // against a tool node whose purl contains the same arch.
    for tool_node in &missing_in_api {
        if node_id_mismatch_api.contains_key(&tool_node.normalized_node_id) {
            continue;
        }
        let tool_purl_joined = tool_node.purl.join(" ");
        let mut best_match: Option<&str> = None;
        for (api_id, _) in &node_id_mismatch_map {
            if let Some(api_node) = api_nodes.get(api_id) {
                if api_node.depth == tool_node.depth
                    && api_node.name == tool_node.name
                    && api_node.relationship == tool_node.relationship
                {
                    if best_match.is_none() {
                        best_match = Some(api_id);
                    }
                    let arch_match = (api_id.contains("amd64")
                        && tool_purl_joined.contains("amd64"))
                        || (api_id.contains("arm64") && tool_purl_joined.contains("arm64"));
                    if arch_match {
                        best_match = Some(api_id);
                        break;
                    }
                }
            }
        }
        if let Some(api_id) = best_match {
            node_id_mismatch_api.insert(tool_node.normalized_node_id.clone(), api_id.to_string());
        }
    }
    if !node_id_mismatch_api.is_empty() {
        log::info!(
            "Detected {} node_id mismatches in missing_in_api (same SHA256, different node_id)",
            node_id_mismatch_api.len()
        );
    }

    let mut field_mismatches = Vec::new();
    let mut structural_mismatches = Vec::new();
    for id in &matched_ids {
        let api_node = &api_nodes[id];
        let tool_node = &tool_nodes[id];
        field_mismatches.extend(compare_fields(api_node, tool_node));
        structural_mismatches.extend(compare_structure(api_node, tool_node));
    }

    Ok(ComparisonResult {
        api_node_count: api_nodes.len(),
        tool_node_count: tool_nodes.len(),
        matched_node_count: matched_ids.len(),
        missing_in_tool,
        missing_in_api,
        field_mismatches,
        structural_mismatches,
        node_id_mismatch_tool: node_id_mismatch_map,
        node_id_mismatch_api,
    })
}

pub fn write_markdown_report(
    result: &ComparisonResult,
    output_path: &str,
) -> Result<(), Box<dyn Error>> {
    let mut report = String::new();

    report.push_str("# Comparison Report: API vs Tool Output\n\n");
    report.push_str(&format!(
        "**Generated:** {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Summary table
    report.push_str("## Summary\n\n");
    report.push_str("| Metric | Count |\n|--------|-------|\n");
    report.push_str(&format!(
        "| API total nodes | {} |\n",
        result.api_node_count
    ));
    report.push_str(&format!(
        "| Tool total nodes | {} |\n",
        result.tool_node_count
    ));
    report.push_str(&format!(
        "| Matched nodes | {} |\n",
        result.matched_node_count
    ));
    report.push_str(&format!(
        "| Missing in tool | {} |\n",
        result.missing_in_tool.len()
    ));
    report.push_str(&format!(
        "| Missing in API | {} |\n",
        result.missing_in_api.len()
    ));
    report.push_str(&format!(
        "| Field mismatches | {} |\n",
        result.field_mismatches.len()
    ));
    report.push_str(&format!(
        "| Structural mismatches | {} |\n",
        result.structural_mismatches.len()
    ));

    // Missing in tool - breakdown by relationship and depth
    if !result.missing_in_tool.is_empty() {
        report.push_str("\n## Nodes Missing in Tool\n\n");

        let mut by_relationship: HashMap<String, usize> = HashMap::new();
        let mut by_depth: HashMap<usize, usize> = HashMap::new();
        let mut with_warnings = 0;
        for node in &result.missing_in_tool {
            let rel = node
                .relationship
                .clone()
                .unwrap_or_else(|| "(root)".to_string());
            *by_relationship.entry(rel).or_insert(0) += 1;
            *by_depth.entry(node.depth).or_insert(0) += 1;
            if !node.warnings.is_empty() {
                with_warnings += 1;
            }
        }

        report.push_str("### By Relationship Type\n\n");
        report.push_str("| Relationship | Count |\n|-------------|-------|\n");
        let mut rel_entries: Vec<_> = by_relationship.iter().collect();
        rel_entries.sort_by(|a, b| b.1.cmp(a.1));
        for (rel, count) in &rel_entries {
            report.push_str(&format!("| {} | {} |\n", rel, count));
        }

        report.push_str("\n### By Depth Level\n\n");
        report.push_str("| Depth | Count |\n|-------|-------|\n");
        let mut depth_entries: Vec<_> = by_depth.iter().collect();
        depth_entries.sort_by_key(|&(d, _)| d);
        for (depth, count) in &depth_entries {
            report.push_str(&format!("| {} | {} |\n", depth, count));
        }

        report.push_str(&format!(
            "\nNodes with warnings from TPA API (e.g. unable to resolve external references): **{}**\n\
             \nNote: The `has_warnings` and `warnings` fields in `missing_in_tool.csv` are sourced \
             directly from the TPA API's analysis response. They indicate issues the API encountered \
             while building its own graph (e.g. `\"Unable to resolve external node: ...\"`). These are \
             not generated by Camp Ranger.\n",
            with_warnings
        ));

        report.push_str("\n### Sample Missing Nodes (first 20)\n\n");
        report.push_str("| Node ID | Name | Depth | Relationship |\n");
        report.push_str("|---------|------|-------|--------------|\n");
        for node in result.missing_in_tool.iter().take(20) {
            report.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                truncate(&node.normalized_node_id, 60),
                truncate(&node.name, 40),
                node.depth,
                node.relationship.as_deref().unwrap_or("(root)")
            ));
        }
    }

    // Missing in API
    if !result.missing_in_api.is_empty() {
        report.push_str("\n## Nodes Missing in API\n\n");
        report.push_str("| Node ID | Name | Depth | Relationship |\n");
        report.push_str("|---------|------|-------|--------------|\n");
        for node in &result.missing_in_api {
            report.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                truncate(&node.normalized_node_id, 60),
                truncate(&node.name, 40),
                node.depth,
                node.relationship.as_deref().unwrap_or("(root)")
            ));
        }
    }

    // Field mismatches
    if !result.field_mismatches.is_empty() {
        report.push_str("\n## Field Mismatches\n\n");
        report.push_str(&format!(
            "Found **{}** field-level mismatches across matched nodes.\n\n",
            result.field_mismatches.len()
        ));

        let mut by_field: HashMap<String, usize> = HashMap::new();
        for fm in &result.field_mismatches {
            *by_field.entry(fm.field_name.clone()).or_insert(0) += 1;
        }
        report.push_str("### By Field\n\n");
        report.push_str("| Field | Mismatch Count |\n|-------|----------------|\n");
        let mut field_entries: Vec<_> = by_field.iter().collect();
        field_entries.sort_by(|a, b| b.1.cmp(a.1));
        for (field, count) in &field_entries {
            report.push_str(&format!("| {} | {} |\n", field, count));
        }

        report.push_str("\n### Sample Mismatches (first 30)\n\n");
        report.push_str("| Node ID | Field | API Value | Tool Value |\n");
        report.push_str("|---------|-------|-----------|------------|\n");
        for fm in result.field_mismatches.iter().take(30) {
            report.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                truncate(&fm.node_id, 50),
                fm.field_name,
                truncate(&fm.api_value, 40),
                truncate(&fm.tool_value, 40)
            ));
        }
    }

    // Structural mismatches
    if !result.structural_mismatches.is_empty() {
        report.push_str("\n## Structural Mismatches\n\n");
        report.push_str(&format!(
            "Found **{}** structural mismatches (parent/children differ).\n\n",
            result.structural_mismatches.len()
        ));

        let mut by_type: HashMap<String, usize> = HashMap::new();
        for sm in &result.structural_mismatches {
            *by_type.entry(sm.mismatch_type.clone()).or_insert(0) += 1;
        }
        report.push_str("### By Type\n\n");
        report.push_str("| Type | Count |\n|------|-------|\n");
        for (t, count) in &by_type {
            report.push_str(&format!("| {} | {} |\n", t, count));
        }

        report.push_str("\n### Sample Structural Mismatches (first 20)\n\n");
        report.push_str("| Node ID | Type | API | Tool |\n");
        report.push_str("|---------|------|-----|------|\n");
        for sm in result.structural_mismatches.iter().take(20) {
            report.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                truncate(&sm.node_id, 50),
                sm.mismatch_type,
                truncate(&sm.api_value, 40),
                truncate(&sm.tool_value, 40)
            ));
        }
    }

    // Verdict
    report.push_str("\n## Verdict\n\n");
    let total_issues = result.missing_in_tool.len()
        + result.missing_in_api.len()
        + result.field_mismatches.len()
        + result.structural_mismatches.len();
    if total_issues == 0 {
        report.push_str("**PASS** - API and tool outputs match perfectly.\n");
    } else {
        report.push_str(&format!(
            "**{} total differences found.** Review the details above and the CSV files for full data.\n",
            total_issues
        ));
    }

    std::fs::write(output_path, report)?;
    log::info!("Written report to {}", output_path);
    Ok(())
}

fn write_missing_in_tool_csv(
    path: &str,
    nodes: &[NormalizedNode],
    mismatch_map: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    for node in nodes {
        let (mismatch_flag, tool_id) = match mismatch_map.get(&node.normalized_node_id) {
            Some(id) => ("yes".to_string(), id.clone()),
            None => ("no".to_string(), String::new()),
        };
        wtr.serialize(MissingInToolRecord {
            api_node_id: node.normalized_node_id.clone(),
            name: node.name.clone(),
            version: node.version.clone(),
            purl: node.purl.join("; "),
            cpe: node.cpe.join("; "),
            published: node.published.clone(),
            relationship: node.relationship.clone().unwrap_or_default(),
            depth_level: node.depth,
            sbom_id: node.sbom_id.clone().unwrap_or_default(),
            document_id: node.document_id.clone().unwrap_or_default(),
            has_warnings: if node.warnings.is_empty() {
                "no".to_string()
            } else {
                format!("yes ({})", node.warnings.len())
            },
            warnings: node.warnings.join("; "),
            node_id_mismatch: mismatch_flag,
            tool_node_id: tool_id,
        })?;
    }
    wtr.flush()?;
    log::info!("Written {} ({} records)", path, nodes.len());
    Ok(())
}

fn write_missing_in_api_csv(
    path: &str,
    nodes: &[NormalizedNode],
    mismatch_map: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    for node in nodes {
        let (mismatch_flag, api_id) = match mismatch_map.get(&node.normalized_node_id) {
            Some(id) => ("yes".to_string(), id.clone()),
            None => ("no".to_string(), String::new()),
        };
        wtr.serialize(MissingInApiRecord {
            tool_node_id: node.normalized_node_id.clone(),
            name: node.name.clone(),
            version: node.version.clone(),
            purl: node.purl.join("; "),
            cpe: node.cpe.join("; "),
            published: node.published.clone(),
            relationship: node.relationship.clone().unwrap_or_default(),
            depth_level: node.depth,
            sbom_id: node.sbom_id.clone().unwrap_or_default(),
            document_id: node.document_id.clone().unwrap_or_default(),
            has_warnings: if node.warnings.is_empty() {
                "no".to_string()
            } else {
                format!("yes ({})", node.warnings.len())
            },
            warnings: node.warnings.join("; "),
            node_id_mismatch: mismatch_flag,
            api_node_id: api_id,
        })?;
    }
    wtr.flush()?;
    log::info!("Written {} ({} records)", path, nodes.len());
    Ok(())
}

pub fn write_csv_outputs(result: &ComparisonResult) -> Result<(), Box<dyn Error>> {
    write_missing_in_tool_csv(
        "missing_in_tool.csv",
        &result.missing_in_tool,
        &result.node_id_mismatch_tool,
    )?;
    write_missing_in_api_csv(
        "missing_in_api.csv",
        &result.missing_in_api,
        &result.node_id_mismatch_api,
    )?;

    if !result.field_mismatches.is_empty() {
        let mut wtr = csv::Writer::from_path("field_mismatches.csv")?;
        for fm in &result.field_mismatches {
            wtr.serialize(fm)?;
        }
        wtr.flush()?;
        log::info!(
            "Written field_mismatches.csv ({} records)",
            result.field_mismatches.len()
        );
    }

    Ok(())
}

pub fn print_summary(result: &ComparisonResult) {
    println!();
    println!("════════════════════════════════════════════════");
    println!("  COMPARISON SUMMARY");
    println!("════════════════════════════════════════════════");
    println!("API nodes:              {}", result.api_node_count);
    println!("Tool nodes:             {}", result.tool_node_count);
    println!("Matched:                {}", result.matched_node_count);
    println!("────────────────────────────────────────────────");
    println!(
        "Missing in tool:        {} (see missing_in_tool.csv)",
        result.missing_in_tool.len()
    );
    println!(
        "Missing in API:         {} (see missing_in_api.csv)",
        result.missing_in_api.len()
    );
    println!(
        "Field mismatches:       {}{}",
        result.field_mismatches.len(),
        if result.field_mismatches.is_empty() {
            ""
        } else {
            " (see field_mismatches.csv)"
        }
    );
    println!(
        "Structural mismatches:  {}",
        result.structural_mismatches.len()
    );
    println!("════════════════════════════════════════════════");
    println!();
}

pub fn compare_and_export(atlas_file: &str, tool_file: &str) -> Result<(), Box<dyn Error>> {
    log::info!("Loading API/Atlas response from: {}", atlas_file);
    let atlas_content = std::fs::read_to_string(atlas_file)?;
    let atlas_json: serde_json::Value = serde_json::from_str(&atlas_content)?;

    log::info!("Loading tool output from: {}", tool_file);
    let tool_content = std::fs::read_to_string(tool_file)?;
    let tool_json: serde_json::Value = serde_json::from_str(&tool_content)?;

    let result = compare_hierarchies(&atlas_json, &tool_json)?;
    write_markdown_report(&result, "comparison_report.md")?;
    write_csv_outputs(&result)?;
    print_summary(&result);
    Ok(())
}
