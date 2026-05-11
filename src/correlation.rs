use crate::fetch_tpa::{
    fetch_tpa_sbom, get_individual_sbom, load_sboms_from_dir, save_sbom_to_file,
};
use crate::tpa_sbom::TpaSbom;
use crate::TpaConfig;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Extract SHA256 hash from a purl string
/// Example: "pkg:oci/name@sha256:abc123..." -> Some("abc123...")
/// Handles both URL-encoded (@sha256%3A) and normal (@sha256:) formats
pub fn extract_sha256_from_purl(purl: &str) -> Option<String> {
    // Try URL-encoded format first (@sha256%3A)
    if let Some(at_pos) = purl.find("@sha256%3A") {
        let hash_start = at_pos + 10; // Length of "@sha256%3A"
        let hash_part = &purl[hash_start..];

        // Extract hash until we hit '?' (query params) or end of string
        let hash = if let Some(query_pos) = hash_part.find('?') {
            &hash_part[..query_pos]
        } else {
            hash_part
        };

        return Some(hash.to_string());
    }

    // Try normal format (@sha256:)
    if let Some(at_pos) = purl.find("@sha256:") {
        let hash_start = at_pos + 8; // Length of "@sha256:"
        let hash_part = &purl[hash_start..];

        // Extract hash until we hit '?' (query params) or end of string
        let hash = if let Some(query_pos) = hash_part.find('?') {
            &hash_part[..query_pos]
        } else {
            hash_part
        };

        return Some(hash.to_string());
    }

    None
}

/// Check if two purls contain the same SHA256 hash
pub fn purls_match_by_sha256(purl1: &str, purl2: &str) -> bool {
    match (
        extract_sha256_from_purl(purl1),
        extract_sha256_from_purl(purl2),
    ) {
        (Some(hash1), Some(hash2)) => hash1 == hash2,
        _ => false,
    }
}

/// Extract name and version from a purl string.
/// Name extraction is type-aware:
///   - golang: namespace/name + subpath (full module path)
///   - others (rpm, etc.): leaf name only (after last /)
/// Version is URL-decoded with epoch qualifier prepended if present.
/// Examples:
///   pkg:golang/github.com/beorn7/perks@v1.0.1?package-id=xxx -> ("github.com/beorn7/perks", "v1.0.1")
///   pkg:golang/github.com/kubernetes-csi/external-snapshotter@v4.2.0#client/v4 -> ("github.com/kubernetes-csi/external-snapshotter/client/v4", "v4.2.0")
///   pkg:rpm/redhat/zlib@1.2.11-40.el9?arch=aarch64&epoch=1 -> ("zlib", "1:1.2.11-40.el9")
///   pkg:golang/github.com/evanphx/json-patch@v5.6.0%2Bincompatible -> ("github.com/evanphx/json-patch", "v5.6.0+incompatible")
fn extract_name_version_from_purl(purl: &str) -> (String, String) {
    if let Some(at_pos) = purl.rfind('@') {
        let name_part = &purl[..at_pos];
        let version_and_rest = &purl[at_pos + 1..];

        // Split version from qualifiers+subpath
        let (version_raw, qualifiers_str) = if let Some(query_pos) = version_and_rest.find('?') {
            (&version_and_rest[..query_pos], Some(&version_and_rest[query_pos + 1..]))
        } else {
            (version_and_rest, None)
        };

        // Extract #subpath (can appear after version or after qualifiers)
        let subpath = version_raw.find('#').map(|pos| &version_raw[pos + 1..])
            .or_else(|| {
                qualifiers_str.and_then(|qs| qs.find('#').map(|pos| &qs[pos + 1..]))
            });

        // Strip #subpath from version
        let version_raw = if let Some(hash_pos) = version_raw.find('#') {
            &version_raw[..hash_pos]
        } else {
            version_raw
        };

        // URL-decode the version
        let version_decoded = urlencoding::decode(version_raw)
            .unwrap_or(std::borrow::Cow::Borrowed(version_raw))
            .into_owned();

        // Check for epoch qualifier and prepend to version
        let epoch = qualifiers_str.and_then(|qs| {
            let qs = if let Some(hash_pos) = qs.find('#') { &qs[..hash_pos] } else { qs };
            qs.split('&')
                .find_map(|pair| {
                    let mut kv = pair.splitn(2, '=');
                    match (kv.next(), kv.next()) {
                        (Some("epoch"), Some(v)) => Some(v.to_string()),
                        _ => None,
                    }
                })
        });

        let version = match epoch {
            Some(e) => format!("{}:{}", e, version_decoded),
            None => version_decoded,
        };

        // Determine PURL type for type-aware name extraction
        let is_golang = name_part.starts_with("pkg:golang/");

        let name = if is_golang {
            // golang: use full namespace/name path, append subpath if present
            let base = if let Some(slash_pos) = name_part.find('/') {
                &name_part[slash_pos + 1..]
            } else {
                name_part
            };
            match subpath {
                Some(sp) if !sp.is_empty() => format!("{}/{}", base, sp),
                _ => base.to_string(),
            }
        } else {
            // rpm, oci, etc.: use leaf name only (after last /)
            if let Some(slash_pos) = name_part.rfind('/') {
                name_part[slash_pos + 1..].to_string()
            } else {
                name_part.to_string()
            }
        };

        // URL-decode the name
        let name = urlencoding::decode(&name)
            .unwrap_or(std::borrow::Cow::Borrowed(&name))
            .into_owned();

        (name, version)
    } else {
        // No @version — extract name from the purl path
        // Strip ?qualifiers and #subpath first
        let purl_clean = if let Some(query_pos) = purl.find('?') {
            &purl[..query_pos]
        } else {
            purl
        };
        let purl_without_subpath = if let Some(hash_pos) = purl_clean.find('#') {
            &purl_clean[..hash_pos]
        } else {
            purl_clean
        };
        let is_golang = purl_without_subpath.starts_with("pkg:golang/");
        let subpath = purl_clean.find('#').map(|pos| &purl_clean[pos + 1..])
            .or_else(|| purl.find('#').map(|pos| {
                let rest = &purl[pos + 1..];
                if let Some(q) = rest.find('?') { &rest[..q] } else { rest }
            }));

        let name = if is_golang {
            let base = if let Some(slash_pos) = purl_without_subpath.find('/') {
                &purl_without_subpath[slash_pos + 1..]
            } else {
                purl_without_subpath
            };
            match subpath {
                Some(sp) if !sp.is_empty() => format!("{}/{}", base, sp),
                _ => base.to_string(),
            }
        } else if let Some(slash_pos) = purl_without_subpath.rfind('/') {
            purl_without_subpath[slash_pos + 1..].to_string()
        } else {
            purl_without_subpath.to_string()
        };

        let name = urlencoding::decode(&name)
            .unwrap_or(std::borrow::Cow::Borrowed(&name))
            .into_owned();

        (name, String::new())
    }
}

/// Build a HashMap for O(1) dependency lookup by ref (purl)
fn build_dependency_map(sbom: &TpaSbom) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for dep in &sbom.dependencies {
        map.insert(dep.ref_purl.clone(), dep.depends_on.clone());
    }
    map
}

#[derive(Debug, Clone)]
pub struct SbomWithRank {
    pub sbom: TpaSbom,
    pub rank: usize,
    pub referenced_by: Vec<String>, // Serial numbers of parent SBOMs
    pub references: Vec<String>,    // Serial numbers of child SBOMs
}

/// JSON output structures matching the reference format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchyJsonOutput {
    pub items: Vec<HierarchyNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchyNode {
    pub node_id: String,
    pub purl: Vec<String>,
    pub cpe: Vec<String>,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub descendants: Vec<HierarchyNode>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

impl HierarchyNode {
    /// Create a node from TpaSbom metadata
    fn from_sbom(sbom: &TpaSbom, node_id: String) -> Self {
        let metadata_component = sbom.metadata.component.as_ref();

        let cpe = metadata_component
            .and_then(|c| c.evidence.as_ref())
            .and_then(|e| e.identity.as_ref())
            .map(|identities| {
                identities
                    .iter()
                    .filter_map(|i| i.concluded_value.clone())
                    .collect()
            })
            .unwrap_or_default();

        let purl = metadata_component
            .and_then(|c| c.purl.clone())
            .map(|p| vec![p])
            .unwrap_or_default();

        let name = metadata_component
            .and_then(|c| c.name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        // Try to get version from metadata.component, fallback to self-referencing component
        let version = metadata_component
            .and_then(|c| c.version.clone())
            .or_else(|| {
                // Try to find self-referencing component by matching purl
                if let Some(meta_purl) = metadata_component.and_then(|c| c.purl.as_ref()) {
                    sbom.components.iter()
                        .find(|comp| {
                            comp.purl.as_ref().map_or(false, |p| purls_match_by_sha256(p, meta_purl))
                        })
                        .and_then(|comp| comp.version.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "Unknown".to_string());

        Self {
            node_id,
            purl,
            cpe,
            name,
            version,
            published: sbom.metadata.timestamp.clone(),
            relationship: None,
            descendants: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a component node from TpaSbomComponents
    fn from_component(
        component: &crate::tpa_sbom::TpaSbomComponents,
        sbom: &TpaSbom,
        node_id: String,
    ) -> Self {
        let purl = component.purl.clone().map(|p| vec![p]).unwrap_or_default();
        let name = component.name.clone().unwrap_or_else(|| "Unknown".to_string());
        let version = component.version.clone().unwrap_or_default();

        Self {
            node_id,
            purl,
            cpe: Vec::new(),
            name,
            version,
            published: sbom.metadata.timestamp.clone(),
            relationship: Some("generates".to_string()),
            descendants: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a dependency node from just a purl string
    fn from_dependency_purl(purl: String, published: Option<String>) -> Self {
        let (name, version) = extract_name_version_from_purl(&purl);

        Self {
            node_id: purl.clone(),
            purl: vec![purl],
            cpe: Vec::new(),
            name,
            version,
            published,
            relationship: Some("dependency".to_string()),
            descendants: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct SbomCorrelation {
    pub nodes: HashMap<String, SbomWithRank>,
}

impl SbomCorrelation {
    /// Online mode: fetch from API and cache
    pub async fn build_from_api(config: &TpaConfig) -> Result<Self, Box<dyn std::error::Error>> {
        log::info!("Fetching SBOMs from API...");
        let sbom_list = fetch_tpa_sbom(config.clone()).await?;
        log::info!("Found {} SBOMs in list", sbom_list.items.len());
        let mut sboms: HashMap<String, TpaSbom> = HashMap::new();
        for item in &sbom_list.items {
            match get_individual_sbom(config, &item.id).await {
                Ok(sbom) => {
                    log::info!("Fetched SBOM: {} ({})", item.name, sbom.serial_number);
                    if let Err(e) = save_sbom_to_file(&sbom, &config.sbom_output_dir) {
                        log::warn!("Failed to save SBOM to file: {}", e);
                    }
                    sboms.insert(sbom.serial_number.clone(), sbom);
                }
                Err(e) => {
                    log::warn!("Failed to fetch SBOM {}: {}", item.id, e);
                }
            }
        }
        Self::build_correlation(sboms)
    }

    /// Offline mode: read from directory
    pub fn build_from_dir(dir_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        log::info!("Loading SBOMs from directory: {}", dir_path);

        let sbom_list = load_sboms_from_dir(dir_path)?;
        log::info!("Loaded {} SBOMs from directory", sbom_list.len());

        let mut sboms: HashMap<String, TpaSbom> = HashMap::new();
        for sbom in sbom_list {
            sboms.insert(sbom.serial_number.clone(), sbom);
        }

        Self::build_correlation(sboms)
    }

    fn build_correlation(
        sboms: HashMap<String, TpaSbom>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if sboms.is_empty() {
            return Ok(SbomCorrelation {
                nodes: HashMap::new(),
            });
        }
        let (reference_graph, referenced_by) = build_reference_graph(&sboms);
        let ranked_nodes = assign_ranks(&sboms, &reference_graph, &referenced_by);
        Ok(SbomCorrelation {
            nodes: ranked_nodes,
        })
    }

    /// Get all SBOMs of a specific rank
    pub fn get_by_rank(&self, rank: usize) -> Vec<&SbomWithRank> {
        self.nodes
            .values()
            .filter(|node| node.rank == rank)
            .collect()
    }

    /// Get the maximum rank in the correlation
    pub fn max_rank(&self) -> usize {
        self.nodes.values().map(|node| node.rank).max().unwrap_or(0)
    }

    pub fn get_sbom_node_by_cpe(&self, cpe: &str) -> Vec<SbomWithRank> {
        let mut filtered_nodes: Vec<SbomWithRank> = Vec::new();
        for node in self.nodes.values() {
            if let Some(component) = &node.sbom.metadata.component {
                if let Some(evidence) = &component.evidence {
                    if let Some(identity) = &evidence.identity {
                        for identity_item in identity {
                            if let Some(sbom_cpe) = &identity_item.concluded_value {
                                if sbom_cpe == cpe {
                                    filtered_nodes.push(node.clone());
                                    break; // Found match in this SBOM, skip remaining identity entries
                                }
                            }
                        }
                    }
                }
            }
        }
        filtered_nodes
    }

    /// Find SBOM nodes by PURL (matches by SHA256 for OCI packages or exact match)
    pub fn get_sbom_node_by_purl(&self, purl: &str) -> Vec<SbomWithRank> {
        let mut filtered_nodes: Vec<SbomWithRank> = Vec::new();

        for node in self.nodes.values() {
            // Check metadata component purl
            if let Some(component) = &node.sbom.metadata.component {
                if let Some(node_purl) = &component.purl {
                    // Try SHA256 matching for OCI packages, fallback to exact match
                    if purls_match_by_sha256(purl, node_purl) || purl == node_purl {
                        filtered_nodes.push(node.clone());
                        continue;
                    }
                }
            }

            // Also check components within the SBOM
            for component in &node.sbom.components {
                if let Some(component_purl) = &component.purl {
                    if purls_match_by_sha256(purl, component_purl) || purl == component_purl {
                        filtered_nodes.push(node.clone());
                        break;
                    }
                }

                // Check pedigree variants
                if let Some(pedigree) = &component.pedigree {
                    if let Some(variants) = &pedigree.variants {
                        for variant in variants {
                            if let Some(variant_purl) = &variant.purl {
                                if purls_match_by_sha256(purl, variant_purl) || purl == variant_purl {
                                    filtered_nodes.push(node.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        filtered_nodes
    }

    /// Get the complete SBOM hierarchy starting from CPE-matching SBOMs (descendants)
    /// Returns a Vec of hierarchies, where each hierarchy is a Vec of SBOMs starting from one CPE-matching node
    pub fn get_sbom_hierarchy_by_cpe(&self, cpe: &str) -> Vec<Vec<SbomWithRank>> {
        let initial_nodes = self.get_sbom_node_by_cpe(cpe);

        if initial_nodes.is_empty() {
            log::warn!("No SBOMs found matching CPE: {}", cpe);
            return Vec::new();
        }

        let mut hierarchies = Vec::new();

        for node in initial_nodes {
            let mut hierarchy = Vec::new();
            let mut visited = HashSet::new();
            self.collect_references_recursive(&node, &mut hierarchy, &mut visited);
            hierarchies.push(hierarchy);
        }

        let total_sboms: usize = hierarchies.iter().map(|h| h.len()).sum();
        log::info!(
            "Collected {} hierarchies with {} total SBOMs for CPE: {}",
            hierarchies.len(),
            total_sboms,
            cpe
        );
        hierarchies
    }

    /// Get the complete SBOM hierarchy starting from PURL-matching SBOMs (descendants)
    /// Returns a Vec of hierarchies, where each hierarchy is a Vec of SBOMs starting from one PURL-matching node
    pub fn get_sbom_hierarchy_by_purl(&self, purl: &str) -> Vec<Vec<SbomWithRank>> {
        let initial_nodes = self.get_sbom_node_by_purl(purl);

        if initial_nodes.is_empty() {
            log::warn!("No SBOMs found matching PURL: {}", purl);
            return Vec::new();
        }

        let mut hierarchies = Vec::new();

        for node in initial_nodes {
            let mut hierarchy = Vec::new();
            let mut visited = HashSet::new();
            self.collect_references_recursive(&node, &mut hierarchy, &mut visited);
            hierarchies.push(hierarchy);
        }

        let total_sboms: usize = hierarchies.iter().map(|h| h.len()).sum();
        log::info!(
            "Collected {} hierarchies with {} total SBOMs for PURL: {}",
            hierarchies.len(),
            total_sboms,
            purl
        );
        hierarchies
    }

    /// Get ancestor hierarchy starting from PURL-matching SBOMs (going upward)
    /// Returns a Vec of hierarchies, where each hierarchy is a Vec of SBOMs going up to the root
    pub fn get_sbom_ancestors_by_purl(&self, purl: &str) -> Vec<Vec<SbomWithRank>> {
        let initial_nodes = self.get_sbom_node_by_purl(purl);

        if initial_nodes.is_empty() {
            log::warn!("No SBOMs found matching PURL: {}", purl);
            return Vec::new();
        }

        let mut hierarchies = Vec::new();

        for node in initial_nodes {
            let mut hierarchy = Vec::new();
            let mut visited = HashSet::new();
            self.collect_ancestors_recursive(&node, &mut hierarchy, &mut visited);
            hierarchies.push(hierarchy);
        }

        let total_sboms: usize = hierarchies.iter().map(|h| h.len()).sum();
        log::info!(
            "Collected {} ancestor hierarchies with {} total SBOMs for PURL: {}",
            hierarchies.len(),
            total_sboms,
            purl
        );
        hierarchies
    }

    /// Recursively collect a node and all its references (descendants)
    fn collect_references_recursive(
        &self,
        node: &SbomWithRank,
        result: &mut Vec<SbomWithRank>,
        visited: &mut HashSet<String>,
    ) {
        // Skip if already visited
        if visited.contains(&node.sbom.serial_number) {
            return;
        }

        // Mark as visited and add to result
        visited.insert(node.sbom.serial_number.clone());
        result.push(node.clone());

        if node.rank == 0 {
            log::info!(
                "Including disconnected node (rank 0): {}",
                node.sbom.serial_number
            );
        }

        log::debug!(
            "Collected rank {} SBOM: {} (references: {})",
            node.rank,
            node.sbom.serial_number,
            node.references.len()
        );

        // Recursively process all child references
        for child_serial in &node.references {
            if let Some(child_node) = self.nodes.get(child_serial) {
                self.collect_references_recursive(child_node, result, visited);
            } else {
                log::warn!("Referenced SBOM not found: {}", child_serial);
            }
        }
    }

    /// Recursively collect a node and all its ancestors (going upward)
    fn collect_ancestors_recursive(
        &self,
        node: &SbomWithRank,
        result: &mut Vec<SbomWithRank>,
        visited: &mut HashSet<String>,
    ) {
        // Skip if already visited
        if visited.contains(&node.sbom.serial_number) {
            return;
        }

        // Mark as visited and add to result
        visited.insert(node.sbom.serial_number.clone());
        result.push(node.clone());

        if node.rank == 0 {
            log::info!(
                "Including disconnected node (rank 0): {}",
                node.sbom.serial_number
            );
        }

        log::debug!(
            "Collected rank {} SBOM: {} (referenced_by: {})",
            node.rank,
            node.sbom.serial_number,
            node.referenced_by.len()
        );

        // Recursively process all parent references (going upward)
        for parent_serial in &node.referenced_by {
            if let Some(parent_node) = self.nodes.get(parent_serial) {
                self.collect_ancestors_recursive(parent_node, result, visited);
            } else {
                log::warn!("Parent SBOM not found: {}", parent_serial);
            }
        }
    }

    /// Filter hierarchies to keep only the one with the most recent root timestamp.
    /// Groups by root component name, then picks the hierarchy whose root SBOM has the latest
    /// metadata.timestamp.
    pub fn filter_latest_hierarchy(
        &self,
        hierarchies: Vec<Vec<SbomWithRank>>,
    ) -> Vec<Vec<SbomWithRank>> {
        if hierarchies.len() <= 1 {
            return hierarchies;
        }

        let mut by_name: HashMap<String, Vec<(String, Vec<SbomWithRank>)>> = HashMap::new();

        for hierarchy in hierarchies {
            if let Some(root) = hierarchy.first() {
                let name = root
                    .sbom
                    .metadata
                    .component
                    .as_ref()
                    .and_then(|c| c.name.clone())
                    .unwrap_or_else(|| root.sbom.serial_number.clone());

                let timestamp = root
                    .sbom
                    .metadata
                    .timestamp
                    .clone()
                    .unwrap_or_default();

                by_name
                    .entry(name)
                    .or_default()
                    .push((timestamp, hierarchy));
            }
        }

        let mut result = Vec::new();
        for (name, mut entries) in by_name {
            entries.sort_by(|a, b| b.0.cmp(&a.0));
            if let Some((ts, hierarchy)) = entries.into_iter().next() {
                log::info!(
                    "Latest hierarchy for '{}': timestamp={}",
                    name,
                    ts
                );
                result.push(hierarchy);
            }
        }

        log::info!(
            "Filtered to {} latest hierarchy/hierarchies",
            result.len()
        );
        result
    }

    /// Convert hierarchies to JSON output format
    pub fn hierarchies_to_json(&self, hierarchies: &[Vec<SbomWithRank>]) -> HierarchyJsonOutput {
        let mut items = Vec::new();

        for hierarchy in hierarchies {
            if let Some(root_node) = hierarchy.first() {
                let json_node = self.build_hierarchy_node(root_node, hierarchy, &mut HashSet::new());
                items.push(json_node);
            }
        }

        HierarchyJsonOutput { items }
    }

    /// Recursively build hierarchy node with descendants
    fn build_hierarchy_node(
        &self,
        node: &SbomWithRank,
        hierarchy: &[SbomWithRank],
        visited: &mut HashSet<String>,
    ) -> HierarchyNode {
        visited.insert(node.sbom.serial_number.clone());

        let node_name = node
            .sbom
            .metadata
            .component
            .as_ref()
            .and_then(|c| c.name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        log::debug!(
            "Building JSON node for '{}' (rank {}, {} references, {} components)",
            node_name,
            node.rank,
            node.references.len(),
            node.sbom.components.len()
        );

        // Create base node from SBOM
        let mut hierarchy_node = HierarchyNode::from_sbom(&node.sbom, node_name.clone());

        // Get this SBOM's own purl for self-reference checking
        let own_purl = node.sbom
            .metadata
            .component
            .as_ref()
            .and_then(|c| c.purl.clone());

        // Build descendants from ALL components
        for component in &node.sbom.components {
            // Check component purl - only add if NOT a self-reference
            if let Some(component_purl) = &component.purl {
                // Check for self-references
                let is_self_reference = if let Some(ref own) = own_purl {
                    purls_match_by_sha256(component_purl, own)
                } else {
                    false
                };

                if !is_self_reference {
                    // Create component node
                    let mut component_node = HierarchyNode::from_component(
                        component,
                        &node.sbom,
                        component_purl.clone(),
                    );

                    // Check if this component references a child SBOM
                    for child_serial in &node.references {
                        if visited.contains(child_serial) {
                            continue;
                        }

                        if let Some(child_node) = hierarchy.iter().find(|n| &n.sbom.serial_number == child_serial) {
                            if let Some(child_purl) = &child_node.sbom.metadata.component.as_ref().and_then(|c| c.purl.clone()) {
                                if purls_match_by_sha256(component_purl, child_purl) {
                                    log::debug!(
                                        "  Adding descendant (component): '{}' -> '{}'",
                                        node_name,
                                        child_node.sbom.metadata.component.as_ref()
                                            .and_then(|c| c.name.as_ref())
                                            .unwrap_or(&"Unknown".to_string())
                                    );

                                    // Add the child SBOM as descendant of this component
                                    let mut child_json = self.build_hierarchy_node(child_node, hierarchy, visited);
                                    child_json.relationship = Some("package".to_string());
                                    component_node.descendants.push(child_json);
                                    break;
                                }
                            }
                        }
                    }

                    // Add component to hierarchy (with or without child SBOM)
                    hierarchy_node.descendants.push(component_node);
                } else {
                    log::debug!("  Skipping self-reference component: {}", component_purl);
                }
            }

            // Check pedigree variants (process even for self-reference components)
            if let Some(pedigree) = &component.pedigree {
                if let Some(variants) = &pedigree.variants {
                    for variant in variants {
                        if let Some(variant_purl) = &variant.purl {
                            // Create component node using variant purl
                            let mut component_node = HierarchyNode::from_component(
                                component,
                                &node.sbom,
                                variant_purl.clone(),
                            );
                            component_node.purl = vec![variant_purl.clone()];

                            // Check if this variant references a child SBOM
                            for child_serial in &node.references {
                                if visited.contains(child_serial) {
                                    continue;
                                }

                                if let Some(child_node) = hierarchy.iter().find(|n| &n.sbom.serial_number == child_serial) {
                                    if let Some(child_purl) = &child_node.sbom.metadata.component.as_ref().and_then(|c| c.purl.clone()) {
                                        if purls_match_by_sha256(variant_purl, child_purl) {
                                            log::debug!(
                                                "  Adding descendant (variant): '{}' -> '{}'",
                                                node_name,
                                                child_node.sbom.metadata.component.as_ref()
                                                    .and_then(|c| c.name.as_ref())
                                                    .unwrap_or(&"Unknown".to_string())
                                            );

                                            // Add the child SBOM as descendant of this component
                                            let mut child_json = self.build_hierarchy_node(child_node, hierarchy, visited);
                                            child_json.relationship = Some("package".to_string());
                                            component_node.descendants.push(child_json);
                                            break;
                                        }
                                    }
                                }
                            }

                            // Add variant component to hierarchy (with or without child SBOM)
                            hierarchy_node.descendants.push(component_node);
                        }
                    }
                }
            }
        }

        // Process dependencies for each component
        let dependency_map = build_dependency_map(&node.sbom);
        let published = node.sbom.metadata.timestamp.clone();

        log::info!(
            "Dependency map for '{}' has {} entries",
            node_name,
            dependency_map.len()
        );

        // Check if SBOM's own component has dependencies (for self-referencing components)
        if let Some(own_purl) = &own_purl {
            // Try to find dependencies for the self-referencing component
            let self_dep_purls = if let Some(deps) = dependency_map.get(own_purl) {
                Some(deps)
            } else {
                // Try matching by SHA256 for OCI packages
                dependency_map.iter()
                    .find(|(ref_purl, _)| purls_match_by_sha256(own_purl, ref_purl))
                    .map(|(_, deps)| deps)
            };

            if let Some(dep_purls) = self_dep_purls {
                log::info!(
                    "  SBOM '{}' (self-reference) has {} dependencies",
                    node_name,
                    dep_purls.len()
                );

                // Add each dependency directly to the SBOM node
                for dep_purl in dep_purls {
                    let dep_node = HierarchyNode::from_dependency_purl(
                        dep_purl.clone(),
                        published.clone(),
                    );
                    hierarchy_node.descendants.push(dep_node);
                }
            }
        }

        // Iterate through descendants and add their dependencies
        let mut descendants_with_deps = Vec::new();
        for mut component_node in hierarchy_node.descendants {
            // Look up dependencies for this component's purl (node_id)
            // Try exact match first, then SHA256 match for OCI packages
            let dep_purls = if let Some(deps) = dependency_map.get(&component_node.node_id) {
                Some(deps)
            } else {
                // Try matching by SHA256 for OCI packages
                dependency_map.iter()
                    .find(|(ref_purl, _)| purls_match_by_sha256(&component_node.node_id, ref_purl))
                    .map(|(_, deps)| deps)
            };

            if let Some(dep_purls) = dep_purls {
                log::info!(
                    "  Component '{}' has {} dependencies",
                    component_node.name,
                    dep_purls.len()
                );

                // Add each dependency as a child of this component
                for dep_purl in dep_purls {
                    let dep_node = HierarchyNode::from_dependency_purl(
                        dep_purl.clone(),
                        published.clone(),
                    );
                    component_node.descendants.push(dep_node);
                }
            }

            descendants_with_deps.push(component_node);
        }

        hierarchy_node.descendants = descendants_with_deps;

        log::debug!(
            "Finished building node '{}' with {} total descendants (including dependencies)",
            node_name,
            hierarchy_node.descendants.len()
        );

        hierarchy_node
    }
}

/// Build reference graph: Map of serial_number -> list of serial_numbers it references
/// Returns (forward_graph, reverse_graph) where:
/// - forward_graph: parent -> [children]
/// - reverse_graph: child -> [parents]
fn build_reference_graph(sboms: &HashMap<String, TpaSbom>) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut referenced_by: HashMap<String, Vec<String>> = HashMap::new();

    for (serial, sbom) in sboms {
        let mut references = Vec::new();

        // Get this SBOM's own purl for self-reference checking
        let own_purl = sbom
            .metadata
            .component
            .as_ref()
            .and_then(|c| c.purl.clone());

        for component in &sbom.components {
            // Check component purl (skip self-references)
            if let Some(component_purl) = &component.purl {
                //log::debug!("Checking component purl: {} in SBOM {}", component_purl, serial);

                // Check if this is a self-reference
                let is_self_reference = if let Some(ref own) = own_purl {
                    purls_match_by_sha256(component_purl, own)
                } else {
                    false
                };

                if is_self_reference {
                    log::info!("Skipping self-reference component purl in {}", serial);
                } else {
                    // Check if this component references another SBOM
                    for (child_serial, child_sbom) in sboms {
                        if child_serial == serial {
                            continue; // Optimization: skip self
                        }

                        if let Some(child_purl) = &child_sbom
                            .metadata
                            .component
                            .as_ref()
                            .and_then(|c| c.purl.clone())
                        {
                            //log::debug!("  Comparing with child purl: {}", child_purl);
                            if purls_match_by_sha256(component_purl, child_purl) {
                                log::info!("Component reference: {} -> {}", serial, child_serial);
                                if !references.contains(child_serial) {
                                    references.push(child_serial.clone());
                                    // Build reverse graph at the same time
                                    referenced_by
                                        .entry(child_serial.clone())
                                        .or_insert_with(Vec::new)
                                        .push(serial.clone());
                                }
                            }
                        } else {
                            log::debug!("  Child {} has no metadata.component.purl", child_serial);
                        }
                    }
                }
            } else {
                log::debug!("Component in {} has no purl", serial);
            }

            // Check pedigree variants (always child references, never self-references)
            if let Some(pedigree) = &component.pedigree {
                if let Some(variants) = &pedigree.variants {
                    log::debug!("Found {} variants in component", variants.len());
                    for variant in variants {
                        if let Some(variant_purl) = &variant.purl {
                            log::debug!("Checking variant purl: {}", variant_purl);
                            for (child_serial, child_sbom) in sboms {
                                if child_serial == serial {
                                    continue; // Optimization: skip self
                                }

                                if let Some(child_purl) = &child_sbom
                                    .metadata
                                    .component
                                    .as_ref()
                                    .and_then(|c| c.purl.clone())
                                {
                                    if purls_match_by_sha256(variant_purl, child_purl) {
                                        log::info!(
                                            "Variant reference: {} -> {}",
                                            serial,
                                            child_serial
                                        );
                                        if !references.contains(child_serial) {
                                            references.push(child_serial.clone());
                                            // Build reverse graph at the same time
                                            referenced_by
                                                .entry(child_serial.clone())
                                                .or_insert_with(Vec::new)
                                                .push(serial.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        graph.insert(serial.clone(), references);
    }

    (graph, referenced_by)
}

/// Assign ranks using BFS level-order traversal
fn assign_ranks(
    sboms: &HashMap<String, TpaSbom>,
    reference_graph: &HashMap<String, Vec<String>>,
    referenced_by: &HashMap<String, Vec<String>>,
) -> HashMap<String, SbomWithRank> {
    let mut ranked_nodes: HashMap<String, SbomWithRank> = HashMap::new();

    // Find all Rank 1 nodes (not referenced by anyone), referenced_by is the reverse of reference_graph
    let mut rank_1_nodes: Vec<String> = Vec::new();
    for serial in sboms.keys() {
        if !referenced_by.contains_key(serial) {
            rank_1_nodes.push(serial.clone());
            log::info!("Rank 1 SBOM: {}", serial);
        }
    }
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();

    // Start with Rank 1 nodes
    for serial in &rank_1_nodes {
        queue.push_back((serial.clone(), 1));
    }

    while let Some((serial, rank)) = queue.pop_front() {
        if visited.contains(&serial) {
            continue;
        }
        visited.insert(serial.clone());

        if let Some(sbom) = sboms.get(&serial) {
            let references = reference_graph.get(&serial).cloned().unwrap_or_default();
            let refs_by = referenced_by.get(&serial).cloned().unwrap_or_default();

            ranked_nodes.insert(
                serial.clone(),
                SbomWithRank {
                    sbom: sbom.clone(),
                    rank,
                    referenced_by: refs_by,
                    references: references.clone(),
                },
            );

            log::info!("Assigned Rank {} to SBOM: {}", rank, serial);

            // Add children to queue with next rank
            for child_serial in &references {
                if !visited.contains(child_serial) {
                    queue.push_back((child_serial.clone(), rank + 1));
                }
            }
        }
    }

    // Handle any disconnected nodes (shouldn't happen in a proper SBOM hierarchy)
    for (serial, sbom) in sboms {
        if !visited.contains(serial) {
            log::warn!("Disconnected SBOM found: {}", serial);
            ranked_nodes.insert(
                serial.clone(),
                SbomWithRank {
                    sbom: sbom.clone(),
                    rank: 0, // Special rank for disconnected nodes
                    referenced_by: referenced_by.get(serial).cloned().unwrap_or_default(),
                    references: reference_graph.get(serial).cloned().unwrap_or_default(),
                },
            );
        }
    }

    ranked_nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_extraction() {
        let purl = "pkg:oci/name@sha256:abc123def456?arch=amd64";
        assert_eq!(
            extract_sha256_from_purl(purl),
            Some("abc123def456".to_string())
        );

        let purl_no_query = "pkg:oci/name@sha256:xyz789";
        assert_eq!(
            extract_sha256_from_purl(purl_no_query),
            Some("xyz789".to_string())
        );

        let purl_no_sha = "pkg:oci/name@v1.0.0";
        assert_eq!(extract_sha256_from_purl(purl_no_sha), None);
    }

    #[test]
    fn test_purl_matching() {
        let purl1 = "pkg:oci/name@sha256:abc123?arch=amd64";
        let purl2 = "pkg:oci/other@sha256:abc123?os=linux";
        assert!(purls_match_by_sha256(purl1, purl2));

        let purl3 = "pkg:oci/name@sha256:different?arch=amd64";
        assert!(!purls_match_by_sha256(purl1, purl3));
    }

    #[test]
    fn test_extract_name_version_golang() {
        let (name, version) = extract_name_version_from_purl(
            "pkg:golang/github.com/beorn7/perks@v1.0.1?package-id=d6fd5b144cc18be1",
        );
        assert_eq!(name, "github.com/beorn7/perks");
        assert_eq!(version, "v1.0.1");
    }

    #[test]
    fn test_extract_name_version_rpm_with_epoch() {
        let (name, version) = extract_name_version_from_purl(
            "pkg:rpm/redhat/gdbm-libs@1.19-4.el9?arch=x86_64&epoch=1",
        );
        assert_eq!(name, "gdbm-libs");
        assert_eq!(version, "1:1.19-4.el9");
    }

    #[test]
    fn test_extract_name_version_url_decode() {
        let (name, version) = extract_name_version_from_purl(
            "pkg:golang/github.com/evanphx/json-patch@v5.6.0%2Bincompatible?package-id=abc",
        );
        assert_eq!(name, "github.com/evanphx/json-patch");
        assert_eq!(version, "v5.6.0+incompatible");
    }

    #[test]
    fn test_extract_name_version_with_subpath() {
        let (name, version) = extract_name_version_from_purl(
            "pkg:golang/github.com/google/renameio@v2.0.0#v2",
        );
        assert_eq!(name, "github.com/google/renameio/v2");
        assert_eq!(version, "v2.0.0");
    }

    #[test]
    fn test_extract_name_version_simple_rpm() {
        let (name, version) = extract_name_version_from_purl(
            "pkg:rpm/redhat/zlib@1.2.11-40.el9?arch=aarch64",
        );
        assert_eq!(name, "zlib");
        assert_eq!(version, "1.2.11-40.el9");
    }

    #[test]
    fn test_extract_name_version_golang_with_subpath() {
        let (name, version) = extract_name_version_from_purl(
            "pkg:golang/github.com/kubernetes-csi/external-snapshotter@v4.2.0#client/v4",
        );
        assert_eq!(name, "github.com/kubernetes-csi/external-snapshotter/client/v4");
        assert_eq!(version, "v4.2.0");
    }
}
