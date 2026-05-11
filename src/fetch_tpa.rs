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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisResponse {
    pub items: Vec<AnalysisNode>,
    pub total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisNode {
    pub sbom_id: Option<String>,
    pub node_id: String,
    #[serde(default)]
    pub purl: Vec<String>,
    #[serde(default)]
    pub cpe: Vec<String>,
    pub name: String,
    pub version: String,
    pub published: String,
    pub document_id: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    #[serde(default)]
    pub relationship: Option<String>,
    #[serde(default)]
    pub descendants: Vec<AnalysisNode>,
    #[serde(default)]
    pub ancestors: Vec<AnalysisNode>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

async fn get_token_with_client(
    client: &reqwest::Client,
    issuer_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response: Response = client
        .post(issuer_url)
        .basic_auth(client_id, Some(client_secret))
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

async fn build_authenticated_client(
    config: &TpaConfig,
) -> Result<(reqwest::Client, Option<String>), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .build()?;

    let token = match (
        &config.issuer_url,
        &config.tpa_api_client_id,
        &config.tpa_api_client_secret,
    ) {
        (Some(issuer), Some(client_id), Some(client_secret)) => {
            log::info!("Authenticating with OIDC credentials");
            Some(get_token_with_client(&client, issuer, client_id, client_secret).await?)
        }
        _ => {
            log::info!("No auth credentials provided; connecting without authentication");
            None
        }
    };
    Ok((client, token))
}

fn attach_auth(
    request: reqwest::RequestBuilder,
    token: &Option<String>,
) -> reqwest::RequestBuilder {
    if let Some(ref t) = token {
        request.header("Authorization", format!("Bearer {}", t))
    } else {
        request
    }
}

pub async fn get_token(config: &TpaConfig) -> Result<String, Box<dyn std::error::Error>> {
    let (_, token) = build_authenticated_client(config).await?;
    token.ok_or_else(|| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No auth credentials provided",
        )) as Box<dyn std::error::Error>
    })
}

pub async fn fetch_tpa_sbom(config: TpaConfig) -> Result<TpaSbomList, Box<dyn std::error::Error>> {
    let (client, token) = build_authenticated_client(&config).await?;
    log::info!("Token/auth ready");

    let url = format!("{}/api/v2/sbom?limit=0", config.tpa_api_url);
    let request = client.get(&url);
    let response: Response = attach_auth(request, &token).send().await?;

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
    let (client, token) = build_authenticated_client(config).await?;
    log::info!("Fetching individual SBOM: {}", sbom_id);

    let url = format!(
        "{}/api/v2/sbom/{}/download",
        config.tpa_api_url,
        encode(sbom_id)
    );
    let request = client.get(&url);
    let response: Response = attach_auth(request, &token).send().await?;

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

pub async fn fetch_analysis_by_cpe(
    config: &TpaConfig,
    cpe: &str,
) -> Result<AnalysisResponse, Box<dyn std::error::Error>> {
    let (client, token) = build_authenticated_client(config).await?;
    let url = format!(
        "{}/api/v2/analysis/component/{}?descendants=10&limit=0",
        config.tpa_api_url,
        encode(cpe)
    );
    log::info!("Fetching analysis by CPE: {}", url);

    let request = client.get(&url);
    let response: Response = attach_auth(request, &token).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let analysis: AnalysisResponse = serde_json::from_str(&text)?;
        log::info!("Analysis returned {} items (total: {})", analysis.items.len(), analysis.total);
        Ok(analysis)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Analysis request failed: {}", response.text().await?),
        )))
    }
}

pub async fn fetch_analysis_by_purl(
    config: &TpaConfig,
    purl: &str,
) -> Result<AnalysisResponse, Box<dyn std::error::Error>> {
    let (client, token) = build_authenticated_client(config).await?;
    let url = format!(
        "{}/api/v2/analysis/component/{}?ancestors=10&limit=0",
        config.tpa_api_url,
        encode(purl)
    );
    log::info!("Fetching analysis by PURL: {}", url);

    let request = client.get(&url);
    let response: Response = attach_auth(request, &token).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let analysis: AnalysisResponse = serde_json::from_str(&text)?;
        log::info!("Analysis returned {} items (total: {})", analysis.items.len(), analysis.total);
        Ok(analysis)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Analysis request failed: {}", response.text().await?),
        )))
    }
}

pub async fn fetch_latest_analysis_by_cpe(
    config: &TpaConfig,
    cpe: &str,
) -> Result<AnalysisResponse, Box<dyn std::error::Error>> {
    let (client, token) = build_authenticated_client(config).await?;
    let url = format!(
        "{}/api/v2/analysis/latest/component/{}?descendants=10&limit=0",
        config.tpa_api_url,
        encode(cpe)
    );
    log::info!("Fetching latest analysis by CPE: {}", url);

    let request = client.get(&url);
    let response: Response = attach_auth(request, &token).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let analysis: AnalysisResponse = serde_json::from_str(&text)?;
        log::info!("Latest analysis returned {} items (total: {})", analysis.items.len(), analysis.total);
        Ok(analysis)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Latest analysis request failed: {}", response.text().await?),
        )))
    }
}

pub async fn fetch_latest_analysis_by_purl(
    config: &TpaConfig,
    purl: &str,
) -> Result<AnalysisResponse, Box<dyn std::error::Error>> {
    let (client, token) = build_authenticated_client(config).await?;
    let url = format!(
        "{}/api/v2/analysis/latest/component/{}?ancestors=10&limit=0",
        config.tpa_api_url,
        encode(purl)
    );
    log::info!("Fetching latest analysis by PURL: {}", url);

    let request = client.get(&url);
    let response: Response = attach_auth(request, &token).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let analysis: AnalysisResponse = serde_json::from_str(&text)?;
        log::info!("Latest analysis returned {} items (total: {})", analysis.items.len(), analysis.total);
        Ok(analysis)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Latest analysis request failed: {}", response.text().await?),
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
