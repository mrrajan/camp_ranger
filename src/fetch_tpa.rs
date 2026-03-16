use crate::tpa_sbom::TpaSbomList;
use crate::TpaConfig;
use reqwest::Response;
use serde_derive::{Deserialize, Serialize};
use urlencoding::encode;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct APIToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
}

pub async fn get_token(config: &TpaConfig) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .build()?;

    let response: Response = client
        .post(&config.issuer_url)
        .basic_auth(
            &config.tpa_api_client_id,
            Some(&config.tpa_api_client_secret),
        )
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    if response.status().is_success() {
        let body: APIToken = serde_json::from_str(&response.text().await?)?;
        Ok(body.access_token)
    } else {
        let error_msg = response.text().await?;
        log::error!("Token request failed: {}", error_msg);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Token request failed: {}", error_msg),
        )))
    }
}

pub async fn fetch_tpa_sbom(config: TpaConfig) -> Result<TpaSbomList, Box<dyn std::error::Error>> {
    let token = get_token(&config).await?;
    log::info!("Token retrieved successfully");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .build()?;

    let url = format!("{}/api/v2/sbom?limit=0", config.tpa_api_url);
    let response: Response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if response.status().is_success() {
        log::info!("SBOM request successful");
        let response_text = response.text().await?;
        let body: TpaSbomList = serde_json::from_str(&response_text)?;
        Ok(body)
    } else {
        log::info!("SBOM request status: {}", &response.status());
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SBOM request failed: {}", response.text().await?),
        )))
    }
}

pub async fn get_individual_sbom(
    config: &TpaConfig,
    sbom_id: &str,
) -> Result<crate::tpa_sbom::TpaSbom, Box<dyn std::error::Error>> {
    let token = get_token(config).await?;
    log::info!("Fetching individual SBOM: {}", sbom_id);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .build()?;

    let url = format!(
        "{}/api/v2/sbom/{}/download",
        config.tpa_api_url,
        encode(sbom_id)
    );

    let response: Response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if response.status().is_success() {
        log::info!("Individual SBOM request successful");
        let response_text = response.text().await?;
        let body: crate::tpa_sbom::TpaSbom = serde_json::from_str(&response_text)?;

        Ok(body)
    } else {
        log::error!("Individual SBOM request status: {}", response.status());
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Individual SBOM request failed: {}", response.text().await?),
        )))
    }
}

pub fn save_sbom_to_file(
    sbom: &crate::tpa_sbom::TpaSbom,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output_dir)?;
    let filename = format!(
        "{}/{}_{}.json",
        output_dir,
        sbom.metadata
            .component
            .as_ref()
            .and_then(|c| c.name.clone())
            .unwrap_or("unknown".to_string())
            .replace("/", "_"),
        sbom.serial_number.replace(":", "_").replace("/", "_")
    );
    let json = serde_json::to_string_pretty(sbom)?;
    std::fs::write(&filename, json)?;
    log::info!("Saved SBOM to {}", filename);
    Ok(())
}

pub fn load_sboms_from_dir(
    dir_path: &str,
) -> Result<Vec<crate::tpa_sbom::TpaSbom>, Box<dyn std::error::Error>> {
    let mut sboms = Vec::new();
    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = std::fs::read_to_string(&path)?;
            let sbom: crate::tpa_sbom::TpaSbom = serde_json::from_str(&content)?;
            log::info!("Loaded SBOM from {:?}", path);
            sboms.push(sbom);
        }
    }
    Ok(sboms)
}
