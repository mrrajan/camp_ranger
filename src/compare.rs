use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;

#[derive(Debug, Deserialize)]
pub struct AtlasResponse {
    pub items: Vec<AtlasNode>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AtlasNode {
    pub node_id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub purl: Vec<String>,
    #[serde(default)]
    pub cpe: Vec<String>,
    pub published: String,
    #[serde(default)]
    pub relationship: Option<String>,
    #[serde(default)]
    pub sbom_id: Option<String>,
    #[serde(default)]
    pub document_id: Option<String>,
    #[serde(default)]
    pub descendants: Vec<AtlasNode>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ToolResponse {
    pub items: Vec<ToolNode>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ToolNode {
    pub node_id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub purl: Vec<String>,
    #[serde(default)]
    pub cpe: Vec<String>,
    pub published: String,
    #[serde(default)]
    pub relationship: Option<String>,
    #[serde(default)]
    pub descendants: Vec<ToolNode>,
}

#[derive(Debug, Serialize)]
pub struct ComparisonRecord {
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

pub struct NodeInfo {
    pub node_id: String,
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
}

/// Recursively collect all nodes from Atlas hierarchy
fn collect_atlas_nodes(node: &AtlasNode, depth: usize, result: &mut HashMap<String, NodeInfo>) {
    let info = NodeInfo {
        node_id: node.node_id.clone(),
        name: node.name.clone(),
        version: node.version.clone(),
        purl: node.purl.clone(),
        cpe: node.cpe.clone(),
        published: node.published.clone(),
        relationship: node.relationship.clone(),
        depth,
        sbom_id: node.sbom_id.clone(),
        document_id: node.document_id.clone(),
        warnings: node.warnings.clone(),
    };
    result.insert(node.node_id.clone(), info);

    for child in &node.descendants {
        collect_atlas_nodes(child, depth + 1, result);
    }
}

/// Recursively collect all nodes from tool hierarchy
fn collect_tool_nodes(node: &ToolNode, depth: usize, result: &mut HashMap<String, NodeInfo>) {
    let info = NodeInfo {
        node_id: node.node_id.clone(),
        name: node.name.clone(),
        version: node.version.clone(),
        purl: node.purl.clone(),
        cpe: node.cpe.clone(),
        published: node.published.clone(),
        relationship: node.relationship.clone(),
        depth,
        sbom_id: None,
        document_id: None,
        warnings: vec![],
    };
    result.insert(node.node_id.clone(), info);

    for child in &node.descendants {
        collect_tool_nodes(child, depth + 1, result);
    }
}

/// Normalize timestamp format for comparison
fn normalize_timestamp(timestamp: &str) -> String {
    // Convert "2025-12-02 12:05:38+00" to "2025-12-02T12:05:38Z"
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

/// Compare Atlas and Tool hierarchies and export differences to CSV
pub fn compare_and_export(
    atlas_file: &str,
    tool_file: &str,
) -> Result<(), Box<dyn Error>> {
    log::info!("Loading Atlas response from: {}", atlas_file);
    let atlas_content = std::fs::read_to_string(atlas_file)?;
    let atlas_response: AtlasResponse = serde_json::from_str(&atlas_content)?;

    log::info!("Loading tool output from: {}", tool_file);
    let tool_content = std::fs::read_to_string(tool_file)?;
    let tool_response: ToolResponse = serde_json::from_str(&tool_content)?;

    if atlas_response.items.is_empty() {
        return Err("Atlas response has no items".into());
    }

    // Find the Dec 2 hierarchy in tool output
    let atlas_root = &atlas_response.items[0];
    let atlas_timestamp = normalize_timestamp(&atlas_root.published);

    log::info!("Atlas hierarchy published: {}", atlas_root.published);
    log::info!("Normalized: {}", atlas_timestamp);

    let tool_root = tool_response
        .items
        .iter()
        .find(|item| {
            let tool_timestamp = normalize_timestamp(&item.published);
            log::info!("Checking tool hierarchy: {} (normalized: {})", item.published, tool_timestamp);
            tool_timestamp == atlas_timestamp
        })
        .ok_or("Could not find matching Dec 2 hierarchy in tool output")?;

    log::info!("Found matching tool hierarchy published: {}", tool_root.published);

    // Collect all nodes from both hierarchies
    let mut atlas_nodes = HashMap::new();
    let mut tool_nodes = HashMap::new();

    collect_atlas_nodes(atlas_root, 0, &mut atlas_nodes);
    collect_tool_nodes(tool_root, 0, &mut tool_nodes);

    log::info!("Atlas total nodes: {}", atlas_nodes.len());
    log::info!("Tool total nodes: {}", tool_nodes.len());

    // Find differences
    let atlas_ids: HashSet<_> = atlas_nodes.keys().cloned().collect();
    let tool_ids: HashSet<_> = tool_nodes.keys().cloned().collect();

    let missing_in_tool: Vec<_> = atlas_ids.difference(&tool_ids).cloned().collect();
    let missing_in_atlas: Vec<_> = tool_ids.difference(&atlas_ids).cloned().collect();

    log::info!("Nodes missing in tool: {}", missing_in_tool.len());
    log::info!("Nodes missing in atlas: {}", missing_in_atlas.len());

    // Export missing_in_tool.csv
    let mut missing_tool_records = Vec::new();
    for node_id in &missing_in_tool {
        if let Some(info) = atlas_nodes.get(node_id) {
            missing_tool_records.push(ComparisonRecord {
                node_id: info.node_id.clone(),
                name: info.name.clone(),
                version: info.version.clone(),
                purl: info.purl.join("; "),
                cpe: info.cpe.join("; "),
                published: info.published.clone(),
                relationship: info.relationship.clone().unwrap_or_default(),
                depth_level: info.depth,
                sbom_id: info.sbom_id.clone().unwrap_or_default(),
                document_id: info.document_id.clone().unwrap_or_default(),
                has_warnings: if info.warnings.is_empty() { "no".to_string() } else { format!("yes ({})", info.warnings.len()) },
            });
        }
    }

    // Sort by depth and name for easier analysis
    missing_tool_records.sort_by(|a, b| {
        a.depth_level
            .cmp(&b.depth_level)
            .then(a.name.cmp(&b.name))
    });

    let mut wtr = csv::Writer::from_path("missing_in_tool.csv")?;
    for record in &missing_tool_records {
        wtr.serialize(record)?;
    }
    wtr.flush()?;
    log::info!("✅ Written missing_in_tool.csv ({} records)", missing_tool_records.len());

    // Export missing_in_atlas.csv
    let mut missing_atlas_records = Vec::new();
    for node_id in &missing_in_atlas {
        if let Some(info) = tool_nodes.get(node_id) {
            missing_atlas_records.push(ComparisonRecord {
                node_id: info.node_id.clone(),
                name: info.name.clone(),
                version: info.version.clone(),
                purl: info.purl.join("; "),
                cpe: info.cpe.join("; "),
                published: info.published.clone(),
                relationship: info.relationship.clone().unwrap_or_default(),
                depth_level: info.depth,
                sbom_id: String::new(),
                document_id: String::new(),
                has_warnings: "no".to_string(),
            });
        }
    }

    missing_atlas_records.sort_by(|a, b| {
        a.depth_level
            .cmp(&b.depth_level)
            .then(a.name.cmp(&b.name))
    });

    let mut wtr = csv::Writer::from_path("missing_in_atlas.csv")?;
    for record in &missing_atlas_records {
        wtr.serialize(record)?;
    }
    wtr.flush()?;
    log::info!("✅ Written missing_in_atlas.csv ({} records)", missing_atlas_records.len());

    // Print summary
    println!("\n════════════════════════════════════════════════");
    println!("📊 COMPARISON SUMMARY");
    println!("════════════════════════════════════════════════");
    println!("Atlas API nodes:        {}", atlas_nodes.len());
    println!("Tool output nodes:      {}", tool_nodes.len());
    println!("Difference:             {}", (atlas_nodes.len() as i32 - tool_nodes.len() as i32).abs());
    println!("────────────────────────────────────────────────");
    println!("Missing in tool:        {} (see missing_in_tool.csv)", missing_in_tool.len());
    println!("Missing in Atlas:       {} (see missing_in_atlas.csv)", missing_in_atlas.len());
    println!("════════════════════════════════════════════════\n");

    Ok(())
}
