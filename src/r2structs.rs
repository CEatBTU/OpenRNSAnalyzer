#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AliasInfo {
    pub role: u64,
    pub role_str: String,
    pub reg: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RegInfo {
    #[serde(rename="type")]
    pub regtype: u64,
    pub type_str: String,
    pub name: String,
    pub size: u64,
    pub offset: u64,
}


#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RegisterProfile {
    pub alias_info: Vec<AliasInfo>,
    pub reg_info: Vec<RegInfo>,
}
