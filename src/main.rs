use clap::{Arg, Command};
use log::info;
use simplelog::*;
mod compare;
mod correlation;
mod fetch_tpa;
mod tpa_sbom;

#[derive(Debug, Clone)]
pub struct TpaConfig {
    pub tpa_api_url: String,
    pub issuer_url: String,
    pub tpa_api_client_id: String,
    pub tpa_api_client_secret: String,
    pub accept_invalid_certs: bool,
    pub sbom_output_dir: String,
}

#[tokio::main]
async fn main() {
    let matches = Command::new("camp_ranger")
        .about(
            "SBOM correlation tool - fetches and correlates SBOMs from TPA API or local directory",
        )
        .arg(
            Arg::new("tpa_api_url")
                .short('a')
                .long("tpa_api_url")
                .help("TPA Application API URL")
                .required_unless_present_any(["sbom_dir", "compare"]),
        )
        .arg(
            Arg::new("issuer_url")
                .short('u')
                .long("issuer_url")
                .help("OIDC Issuer URL for authentication")
                .required_unless_present_any(["sbom_dir", "compare"]),
        )
        .arg(
            Arg::new("tpa_api_client_id")
                .short('i')
                .long("tpa_api_client_id")
                .help("TPA API Client ID")
                .required_unless_present_any(["sbom_dir", "compare"]),
        )
        .arg(
            Arg::new("tpa_api_client_secret")
                .short('s')
                .long("tpa_api_client_secret")
                .help("TPA API Client Secret")
                .required_unless_present_any(["sbom_dir", "compare"]),
        )
        .arg(
            Arg::new("accept_invalid_certs")
                .short('k')
                .long("accept_invalid_certs")
                .help("Accept self-signed/invalid SSL certificates (insecure)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("sbom_dir")
                .short('d')
                .long("sbom_dir")
                .help("Directory containing SBOM JSON files (offline mode)")
                .conflicts_with_all([
                    "tpa_api_url",
                    "issuer_url",
                    "tpa_api_client_id",
                    "tpa_api_client_secret",
                ]),
        )
        .arg(
            Arg::new("cpe")
                .short('c')
                .long("cpe")
                .help("CPE to filter SBOMs (retrieves descendants)")
                .required(false)
                .conflicts_with("purl"),
        )
        .arg(
            Arg::new("purl")
                .short('p')
                .long("purl")
                .help("PURL to filter SBOMs (retrieves ancestors)")
                .required(false)
                .conflicts_with("cpe"),
        )
        .arg(
            Arg::new("compare")
                .long("compare")
                .help("Compare Atlas API response with tool output")
                .num_args(2)
                .value_names(["ATLAS_FILE", "TOOL_FILE"])
                .conflicts_with_all([
                    "tpa_api_url",
                    "issuer_url",
                    "tpa_api_client_id",
                    "tpa_api_client_secret",
                    "sbom_dir",
                    "cpe",
                    "purl",
                ]),
        )
        .get_matches();

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Debug,
            Config::default(),
            std::fs::File::create("camp_ranger_sbom.log").unwrap(),
        ),
    ])
    .unwrap();

    // Handle compare mode if --compare flag is provided
    if let Some(compare_args) = matches.get_many::<String>("compare") {
        let args: Vec<&String> = compare_args.collect();
        if args.len() == 2 {
            let atlas_file = args[0].as_str();
            let tool_file = args[1].as_str();

            match compare::compare_and_export(atlas_file, tool_file) {
                Ok(_) => {
                    info!("Comparison completed successfully");
                }
                Err(e) => {
                    log::error!("Comparison failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
    }

    let correlation = if let Some(sbom_dir) = matches.get_one::<String>("sbom_dir") {
        // Offline mode: read from directory
        info!("Loading SBOMs from directory: {}", sbom_dir);
        correlation::SbomCorrelation::build_from_dir(sbom_dir)
    } else {
        // Online mode: fetch from API and cache
        let config = TpaConfig {
            tpa_api_url: matches.get_one::<String>("tpa_api_url").unwrap().clone(),
            issuer_url: matches.get_one::<String>("issuer_url").unwrap().clone(),
            tpa_api_client_id: matches
                .get_one::<String>("tpa_api_client_id")
                .unwrap()
                .clone(),
            tpa_api_client_secret: matches
                .get_one::<String>("tpa_api_client_secret")
                .unwrap()
                .clone(),
            accept_invalid_certs: matches.get_flag("accept_invalid_certs"),
            sbom_output_dir: "sboms".to_string(),
        };
        info!(
            "Fetching SBOMs from API and saving to: {}",
            config.sbom_output_dir
        );
        correlation::SbomCorrelation::build_from_api(&config).await
    };

    match correlation {
        Ok(corr) => {
            if let Some(cpe) = matches.get_one::<String>("cpe") {
                let hierarchies = corr.get_sbom_hierarchy_by_cpe(cpe);
                if hierarchies.is_empty() {
                    log::error!("CPE not found in any SBOM");
                } else {
                    log::info!("================================================");
                    log::info!("Found {} hierarchy tree(s) for CPE: {}", hierarchies.len(), cpe);
                    log::info!("================================================\n");

                    // Display each hierarchy tree separately
                    for (idx, hierarchy) in hierarchies.iter().enumerate() {
                        let root_node = &hierarchy[0];
                        let root_name = root_node
                            .sbom
                            .metadata
                            .component
                            .as_ref()
                            .and_then(|c| c.name.as_ref())
                            .map(|s| s.as_str())
                            .unwrap_or("Unknown");

                        log::info!("╔════════════════════════════════════════════════");
                        log::info!("║ Hierarchy #{}: {} ({})", idx + 1, root_name, root_node.sbom.serial_number);
                        log::info!("║ Total SBOMs in tree: {}", hierarchy.len());
                        log::info!("╚════════════════════════════════════════════════\n");

                        // Group by rank within this hierarchy
                        let max_rank = hierarchy.iter().map(|n| n.rank).max().unwrap_or(0);
                        for rank in 1..=max_rank {
                            let nodes_at_rank: Vec<_> = hierarchy.iter().filter(|n| n.rank == rank).collect();
                            if !nodes_at_rank.is_empty() {
                                log::info!("  📊 Rank {} ({} SBOM(s)):", rank, nodes_at_rank.len());
                                for node in nodes_at_rank {
                                    let name = node
                                        .sbom
                                        .metadata
                                        .component
                                        .as_ref()
                                        .and_then(|c| c.name.as_ref())
                                        .map(|s| s.as_str())
                                        .unwrap_or("Unknown");
                                    log::info!(
                                        "     └─ {} (Components: {}, References: {})",
                                        name,
                                        node.sbom.components.len(),
                                        node.references.len()
                                    );
                                    log::info!(
                                        "        Serial: {}",
                                        node.sbom.serial_number
                                    );
                                }
                                log::info!("");
                            }
                        }
                    }
                    log::info!("================================================");

                    // Generate JSON output
                    let json_output = corr.hierarchies_to_json(&hierarchies);
                    let output_file = "hierarchy_output.json";
                    match serde_json::to_string_pretty(&json_output) {
                        Ok(json_string) => {
                            match std::fs::write(output_file, json_string) {
                                Ok(_) => {
                                    log::info!("\n✅ Hierarchical JSON output written to: {}", output_file);
                                }
                                Err(e) => {
                                    log::error!("Failed to write JSON file: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to serialize JSON: {}", e);
                        }
                    }
                }
            } else if let Some(purl) = matches.get_one::<String>("purl") {
                let hierarchies = corr.get_sbom_ancestors_by_purl(purl);
                if hierarchies.is_empty() {
                    log::error!("PURL not found in any SBOM");
                } else {
                    log::info!("================================================");
                    log::info!("Found {} ancestor tree(s) for PURL: {}", hierarchies.len(), purl);
                    log::info!("================================================\n");

                    // Display each ancestor tree separately
                    for (idx, hierarchy) in hierarchies.iter().enumerate() {
                        let starting_node = &hierarchy[0];
                        let starting_name = starting_node
                            .sbom
                            .metadata
                            .component
                            .as_ref()
                            .and_then(|c| c.name.as_ref())
                            .map(|s| s.as_str())
                            .unwrap_or("Unknown");

                        log::info!("╔════════════════════════════════════════════════");
                        log::info!("║ Ancestor Tree #{}: {} ({})", idx + 1, starting_name, starting_node.sbom.serial_number);
                        log::info!("║ Total SBOMs in tree: {}", hierarchy.len());
                        log::info!("╚════════════════════════════════════════════════\n");

                        // Group by rank within this hierarchy (ascending order for ancestors)
                        let min_rank = hierarchy.iter().map(|n| n.rank).min().unwrap_or(0);
                        let max_rank = hierarchy.iter().map(|n| n.rank).max().unwrap_or(0);
                        for rank in min_rank..=max_rank {
                            let nodes_at_rank: Vec<_> = hierarchy.iter().filter(|n| n.rank == rank).collect();
                            if !nodes_at_rank.is_empty() {
                                log::info!("  📊 Rank {} ({} SBOM(s)):", rank, nodes_at_rank.len());
                                for node in nodes_at_rank {
                                    let name = node
                                        .sbom
                                        .metadata
                                        .component
                                        .as_ref()
                                        .and_then(|c| c.name.as_ref())
                                        .map(|s| s.as_str())
                                        .unwrap_or("Unknown");
                                    log::info!(
                                        "     └─ {} (Components: {}, Referenced by: {})",
                                        name,
                                        node.sbom.components.len(),
                                        node.referenced_by.len()
                                    );
                                    log::info!(
                                        "        Serial: {}",
                                        node.sbom.serial_number
                                    );
                                }
                                log::info!("");
                            }
                        }
                    }
                    log::info!("================================================");

                    // Generate JSON output for ancestors
                    let json_output = corr.hierarchies_to_json(&hierarchies);
                    let output_file = "ancestor_hierarchy_output.json";
                    match serde_json::to_string_pretty(&json_output) {
                        Ok(json_string) => {
                            match std::fs::write(output_file, json_string) {
                                Ok(_) => {
                                    log::info!("\n✅ Ancestor hierarchical JSON output written to: {}", output_file);
                                }
                                Err(e) => {
                                    log::error!("Failed to write JSON file: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to serialize JSON: {}", e);
                        }
                    }
                }
            } else {
                info!(
                    "Correlation built successfully with {} SBOMs",
                    corr.nodes.len()
                );
                info!("Maximum rank: {}", corr.max_rank());

                for rank in 1..=corr.max_rank() {
                    let sboms_at_rank = corr.get_by_rank(rank);
                    info!("Rank {}: {} SBOM(s)", rank, sboms_at_rank.len());
                    for sbom_node in sboms_at_rank {
                        let name = sbom_node
                            .sbom
                            .metadata
                            .component
                            .as_ref()
                            .and_then(|c| c.name.as_ref())
                            .map(|s| s.as_str())
                            .unwrap_or("Unknown");
                        info!(
                            "  - {} (referenced by: {}, references: {})",
                            name,
                            sbom_node.referenced_by.len(),
                            sbom_node.references.len()
                        );
                    }
                }
            }
        }
        Err(e) => {
            log::error!("Correlation failed: {}", e);
        }
    }
}
