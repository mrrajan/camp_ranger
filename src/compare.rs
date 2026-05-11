use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;

#[derive(Debug, Clone)]
pub struct NormalizedNode {
    pub original_node_id: String,
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
pub struct MissingNodeRecord {
    pub node_id: String,
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
}

pub struct ComparisonResult {
    pub api_node_count: usize,
    pub tool_node_count: usize,
    pub matched_node_count: usize,
    pub missing_in_tool: Vec<NormalizedNode>,
    pub missing_in_api: Vec<NormalizedNode>,
    pub field_mismatches: Vec<FieldMismatch>,
    pub structural_mismatches: Vec<StructuralMismatch>,
}

fn normalize_node_id(node_id: &str) -> String {
    urlencoding::decode(node_id)
        .unwrap_or(std::borrow::Cow::Borrowed(node_id))
        .into_owned()
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

    let mut child_ids = Vec::new();
    if let Some(descs) = descendants {
        for d in descs {
            let child_node_id = d["node_id"].as_str().unwrap_or_default();
            if !child_node_id.is_empty() {
                child_ids.push(normalize_node_id(child_node_id));
            }
        }
    }

    if result.contains_key(&normalized_id) {
        log::debug!("Duplicate normalized_node_id: {}", normalized_id);
    }

    let node = NormalizedNode {
        original_node_id: node_id.to_string(),
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
}

fn compare_fields(
    api_node: &NormalizedNode,
    tool_node: &NormalizedNode,
) -> Vec<FieldMismatch> {
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
    report.push_str(&format!("| API total nodes | {} |\n", result.api_node_count));
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
            let rel = node.relationship.clone().unwrap_or_else(|| "(root)".to_string());
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
            "\nNodes with warnings (unresolved references): **{}**\n",
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

fn write_missing_csv(path: &str, nodes: &[NormalizedNode]) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    for node in nodes {
        wtr.serialize(MissingNodeRecord {
            node_id: node.normalized_node_id.clone(),
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
        })?;
    }
    wtr.flush()?;
    log::info!("Written {} ({} records)", path, nodes.len());
    Ok(())
}

pub fn write_csv_outputs(result: &ComparisonResult) -> Result<(), Box<dyn Error>> {
    write_missing_csv("missing_in_tool.csv", &result.missing_in_tool)?;
    write_missing_csv("missing_in_api.csv", &result.missing_in_api)?;

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

pub fn compare_and_export(
    atlas_file: &str,
    tool_file: &str,
) -> Result<(), Box<dyn Error>> {
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
