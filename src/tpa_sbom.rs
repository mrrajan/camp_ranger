use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomList {
    pub items: Vec<TpaSbomListItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomListItem {
    pub id: String,
    pub name: String,
    pub published: String,
    pub described_by: Option<Vec<TpaSbomListItemDescribedBy>>,
    pub document_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomListItemDescribedBy {
    pub cpe: Vec<String>,
    pub group: Option<String>,
    pub id: String,
    pub purl: Vec<Value>,
    pub version: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbom {
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub metadata: TpaSbomMetadata,
    pub components: Vec<TpaSbomComponents>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomMetadata {
    pub component: Option<TpaSbomMetadataComponent>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomMetadataComponent {
    pub name: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomComponents {
    pub name: Option<String>,
    pub purl: Option<String>,
    pub version: Option<String>,
    pub pedigree: Option<TpaSbomComponentsPedigree>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomComponentsPedigree {
    pub variants: Option<Vec<TpaSbomComponentsPedigreeVariant>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpaSbomComponentsPedigreeVariant {
    pub purl: Option<String>,
    pub version: String,
}