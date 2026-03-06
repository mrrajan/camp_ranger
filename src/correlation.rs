use crate::fetch_tpa::{fetch_tpa_sbom, get_individual_sbom, load_sboms_from_dir, save_sbom_to_file};
use crate::tpa_sbom::TpaSbom;
use crate::TpaConfig;
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
    match (extract_sha256_from_purl(purl1), extract_sha256_from_purl(purl2)) {
        (Some(hash1), Some(hash2)) => hash1 == hash2,
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct SbomWithRank {
    pub sbom: TpaSbom,
    pub rank: usize,
    pub referenced_by: Vec<String>,  // Serial numbers of parent SBOMs
    pub references: Vec<String>,     // Serial numbers of child SBOMs
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
        let reference_graph = build_reference_graph(&sboms);
        let ranked_nodes = assign_ranks(&sboms, &reference_graph);
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
}

/// Build reference graph: Map of serial_number -> list of serial_numbers it references
fn build_reference_graph(sboms: &HashMap<String, TpaSbom>) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

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
                                        log::info!("Variant reference: {} -> {}", serial, child_serial);
                                        if !references.contains(child_serial) {
                                            references.push(child_serial.clone());
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

    graph
}

/// Assign ranks using BFS level-order traversal
fn assign_ranks(
    sboms: &HashMap<String, TpaSbom>,
    reference_graph: &HashMap<String, Vec<String>>,
) -> HashMap<String, SbomWithRank> {
    let mut ranked_nodes: HashMap<String, SbomWithRank> = HashMap::new();

    // Build reverse graph (who is referenced by whom)
    let mut referenced_by: HashMap<String, Vec<String>> = HashMap::new();
    for (parent_serial, children) in reference_graph {
        for child_serial in children {
            referenced_by
                .entry(child_serial.clone())
                .or_insert_with(Vec::new)
                .push(parent_serial.clone());
        }
    }

    // Find all Rank 1 nodes (not referenced by anyone)
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
}
