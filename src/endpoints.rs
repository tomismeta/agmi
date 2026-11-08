//! Paths are configuration; authentication and effect permissions are code contracts.
use anyhow::{Result, ensure};
use reqwest::{Method, Url};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::LazyLock};

// Frozen provenance for journals created before routing profiles were recorded.
pub(crate) const LEGACY_API_FINGERPRINT: &str =
    "bd22f58b3dce70c922dbfd4b7aec5c016261fd031defc86f7d8fa9b5b1e14e16";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    Status,
    Networks,
    NetworkFacts,
    Epochs,
    Identity,
    Challenge,
    Assignments,
    AddressAssignments,
    ExplorerAddress,
    Established,
    Job,
    Receipt,
    ExplorerTx,
    Answer,
    Grade,
    Mine,
    JoinPow,
    Register,
}
impl Endpoint {
    pub const ALL: [Self; 18] = [
        Self::Status,
        Self::Networks,
        Self::NetworkFacts,
        Self::Epochs,
        Self::Identity,
        Self::Challenge,
        Self::Assignments,
        Self::AddressAssignments,
        Self::ExplorerAddress,
        Self::Established,
        Self::Job,
        Self::Receipt,
        Self::ExplorerTx,
        Self::Answer,
        Self::Grade,
        Self::Mine,
        Self::JoinPow,
        Self::Register,
    ];
    pub fn method(self) -> Method {
        if matches!(self, Self::Answer | Self::Grade | Self::Register) {
            Method::POST
        } else {
            Method::GET
        }
    }
    pub fn is_effect(self) -> bool {
        matches!(
            self,
            Self::Answer | Self::Grade | Self::Mine | Self::Register
        )
    }
    pub fn authenticated(self) -> bool {
        matches!(
            self,
            Self::Identity
                | Self::Challenge
                | Self::Assignments
                | Self::Answer
                | Self::Grade
                | Self::Mine
        )
    }
    fn placeholder(self) -> Option<&'static str> {
        match self {
            Self::Job | Self::Receipt | Self::ExplorerTx => Some("{id}"),
            Self::AddressAssignments | Self::ExplorerAddress | Self::Established => {
                Some("{address}")
            }
            _ => None,
        }
    }
    fn valid_parameter(self, value: &str) -> bool {
        match self {
            Self::Receipt | Self::ExplorerTx => {
                value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
            }
            Self::AddressAssignments | Self::ExplorerAddress | Self::Established => {
                crate::config::valid_address(value)
            }
            Self::Job => crate::config::safe_segment(value, 128),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApiEndpoints {
    pub chain_path: String,
    #[serde(flatten)]
    pub routes: BTreeMap<Endpoint, String>,
}
#[derive(Deserialize)]
struct RawApi {
    chain_path: String,
    #[serde(flatten)]
    routes: BTreeMap<Endpoint, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
    base_url: String,
    chain: String,
    trusted_origins: Vec<String>,
    api: RawApi,
}
pub(crate) struct NetworkDefaults {
    pub base_url: String,
    pub chain: String,
    pub trusted_origins: Vec<String>,
    pub api: ApiEndpoints,
}
pub(crate) fn network_defaults() -> &'static NetworkDefaults {
    static DEFAULTS: LazyLock<NetworkDefaults> = LazyLock::new(|| {
        let raw: RawDefaults = toml::from_str(include_str!("../defaults/network.toml"))
            .expect("bundled network defaults must be valid");
        let api = ApiEndpoints {
            chain_path: raw.api.chain_path,
            routes: raw.api.routes,
        };
        api.validate()
            .expect("bundled API defaults must be complete and valid");
        NetworkDefaults {
            base_url: raw.base_url,
            chain: raw.chain,
            trusted_origins: raw.trusted_origins,
            api,
        }
    });
    &DEFAULTS
}
impl Default for ApiEndpoints {
    fn default() -> Self {
        network_defaults().api.clone()
    }
}
impl<'de> Deserialize<'de> for ApiEndpoints {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Overrides {
            chain_path: Option<String>,
            #[serde(flatten)]
            routes: BTreeMap<Endpoint, String>,
        }
        let overrides = Overrides::deserialize(deserializer)?;
        let mut value = Self::default();
        if let Some(path) = overrides.chain_path {
            value.chain_path = path;
        }
        value.routes.extend(overrides.routes);
        Ok(value)
    }
}
fn validate_template(path: &str, placeholder: Option<&str>) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 512 && path.starts_with('/') && !path.contains("//"),
        "API template must be a bounded relative absolute path"
    );
    let rendered = if let Some(token) = placeholder {
        ensure!(
            path.matches(token).count() == 1 && path.split('/').any(|part| part == token),
            "API template requires its exact placeholder segment"
        );
        path.replace(token, "value")
    } else {
        path.to_owned()
    };
    ensure!(
        rendered
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
            && rendered.split('/').all(|part| part != "." && part != ".."),
        "API template contains an unsafe path or unsupported placeholder"
    );
    Ok(())
}

fn templates_overlap(left: &str, right: &str) -> bool {
    left.split('/').count() == right.split('/').count()
        && left
            .split('/')
            .zip(right.split('/'))
            .all(|(a, b)| a == b || a.starts_with('{') || b.starts_with('{'))
}

impl ApiEndpoints {
    pub fn fingerprint(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn validate(&self) -> Result<()> {
        validate_template(&self.chain_path, Some("{chain}"))?;
        ensure!(
            self.routes.len() == Endpoint::ALL.len(),
            "API configuration must contain every endpoint"
        );
        for (index, endpoint) in Endpoint::ALL.into_iter().enumerate() {
            let path = self
                .routes
                .get(&endpoint)
                .ok_or_else(|| anyhow::anyhow!("API endpoint missing"))?;
            validate_template(path, endpoint.placeholder())?;
            for other in Endpoint::ALL.iter().skip(index + 1) {
                if endpoint.method() == other.method() {
                    ensure!(
                        self.routes
                            .get(other)
                            .is_some_and(|other| !templates_overlap(path, other)),
                        "API endpoint paths collide"
                    );
                }
            }
        }
        Ok(())
    }
    pub fn url(
        &self,
        origin: &Url,
        chain: &str,
        endpoint: Endpoint,
        parameter: Option<&str>,
    ) -> Result<Url> {
        ensure!(crate::config::safe_segment(chain, 64), "invalid API chain");
        let template = self
            .routes
            .get(&endpoint)
            .ok_or_else(|| anyhow::anyhow!("API endpoint missing"))?;
        let path = match (endpoint.placeholder(), parameter) {
            (Some(token), Some(value)) if endpoint.valid_parameter(value) => {
                template.replace(token, value)
            }
            (None, None) => template.clone(),
            _ => anyhow::bail!("invalid API endpoint parameter"),
        };
        let prefix = self.chain_path.replace("{chain}", chain);
        let mut url = origin.clone();
        url.set_path(&format!("{}{}", prefix.trim_end_matches('/'), path));
        ensure!(
            url.origin() == origin.origin() && url.query().is_none() && url.fragment().is_none(),
            "API URL escaped its configured origin"
        );
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overridden_routes_render_without_changing_permissions() {
        let api: ApiEndpoints =
            toml::from_str("chain_path='/v2/{chain}'\nchallenge='/questions'\njob='/jobs/{id}'")
                .unwrap();
        api.validate().unwrap();
        let origin = Url::parse("https://example.org").unwrap();
        assert_eq!(
            api.url(&origin, "test", Endpoint::Challenge, None)
                .unwrap()
                .as_str(),
            "https://example.org/v2/test/questions"
        );
        assert_eq!(
            api.url(&origin, "test", Endpoint::Job, Some("bound-job"))
                .unwrap()
                .path(),
            "/v2/test/jobs/bound-job"
        );
        assert!(
            api.url(&origin, "test", Endpoint::Job, Some("../mine"))
                .is_err()
        );
        assert!(Endpoint::Mine.is_effect());
        assert!(Endpoint::Identity.authenticated());
        assert!(!Endpoint::Register.authenticated());
    }
    #[test]
    fn unsafe_templates_and_effect_collisions_fail_closed() {
        for path in [
            "https://example.org/x",
            "//example.org/x",
            "/x?secret=y",
            "/x#y",
            "/x%2fy",
            "/../x",
            "/x/./y",
            "/x\\y",
            "/x/{id}",
        ] {
            let mut api = ApiEndpoints::default();
            api.routes.insert(Endpoint::Challenge, path.into());
            assert!(api.validate().is_err(), "{path}");
        }
        let mut api = ApiEndpoints::default();
        api.routes
            .insert(Endpoint::Challenge, api.routes[&Endpoint::Mine].clone());
        assert!(api.validate().is_err());
        let mut api = ApiEndpoints::default();
        api.routes.insert(
            Endpoint::Mine,
            api.routes[&Endpoint::Job].replace("{id}", "bound-job"),
        );
        assert!(api.validate().is_err());
        assert!(toml::from_str::<ApiEndpoints>("unsupported='/x'").is_err());
    }
}
