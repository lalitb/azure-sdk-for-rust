// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Azure Arc managed identity support (two-step challenge flow).
//
// Protocol (modeled on MSAL Go implementation):
// 1. Initial unauthenticated GET
//    - URL: {IDENTITY_ENDPOINT or default}/?api-version=2020-06-01&resource={resource}
//    - Header: Metadata: true
//    - Expect: 401 with `www-authenticate: Basic realm={path to secret .key file}`
// 2. Read secret file (<=4KB) from validated directory
// 3. Second GET with same query plus header: Authorization: Basic {raw secret contents}
// 4. Expect success JSON payload with access_token and expires_on
//
// Azure Arc does NOT support user-assigned identities. Only system assigned is valid.

use crate::{env::Env, TokenCache, TokenCredentialOptions};
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{http_response_from_body, Error, ErrorKind, ResultExt},
    http::{request::Request, HttpClient, Method, StatusCode, Url},
    json::from_json,
    time::OffsetDateTime,
};
use serde::Deserialize;
use std::{fs, path::Path, sync::Arc};

const API_VERSION: &str = "2020-06-01";
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:40342/metadata/identity/oauth2/token";
const HEADER_METADATA: &str = "metadata";
const HEADER_WWW_AUTHENTICATE: &str = "www-authenticate";
const HEADER_AUTHORIZATION: &str = "authorization";
const ARC_FILE_EXTENSION: &str = ".key";
const ARC_MAX_FILE_SIZE: u64 = 4096;
const ARC_TOKENS_DIR_LINUX: &str = "/var/opt/azcmagent/tokens";
#[cfg(target_os = "windows")]
const ARC_PROGRAM_DATA: &str = "ProgramData";
#[cfg(target_os = "windows")]
const ARC_CONNECTED_MACHINE_DIR: &str = "AzureConnectedMachineAgent";
#[cfg(target_os = "windows")]
const ARC_TOKENS_SUBDIR: &str = "Tokens";

// Test override env var (not documented / internal)
const ARC_TOKENS_DIR_OVERRIDE: &str = "AZURE_IDENTITY_ARC_TOKENS_DIR";

#[derive(Debug)]
pub(crate) struct AzureArcManagedIdentityCredential {
    http_client: Arc<dyn HttpClient>,
    endpoint: Url,
    cache: TokenCache,
    env: Env,
}

impl AzureArcManagedIdentityCredential {
    pub fn new(options: impl Into<TokenCredentialOptions>) -> azure_core::Result<Arc<Self>> {
        let options = options.into();
        let env = options.env().clone();

        // Use IDENTITY_ENDPOINT if provided, else default constant (mirrors MSAL behavior)
        let endpoint = env
            .var("IDENTITY_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let endpoint = Url::parse(&endpoint).with_context(ErrorKind::Credential, || {
            format!("Azure Arc endpoint must be a valid URL, got '{endpoint}'")
        })?;

        Ok(Arc::new(Self {
            http_client: options.http_client(),
            endpoint,
            cache: TokenCache::new(),
            env,
        }))
    }

    fn tokens_dir(&self) -> Option<String> {
        if let Ok(override_dir) = self.env.var(ARC_TOKENS_DIR_OVERRIDE) {
            return Some(override_dir);
        }
        #[cfg(target_os = "windows")]
        {
            if let Ok(program_data) = self.env.var(ARC_PROGRAM_DATA) {
                let p = Path::new(&program_data)
                    .join(ARC_CONNECTED_MACHINE_DIR)
                    .join(ARC_TOKENS_SUBDIR);
                return Some(p.to_string_lossy().to_string());
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            return Some(ARC_TOKENS_DIR_LINUX.to_string());
        }
        #[allow(unreachable_code)]
        None
    }

    async fn get_token_impl(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        if scopes.len() != 1 {
            return Err(Error::message(
                ErrorKind::Credential,
                "Azure Arc managed identity requires exactly one scope",
            ));
        }
        let resource = scopes[0].strip_suffix("/.default").unwrap_or(scopes[0]);

        // Phase 1: initial challenge
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .append_pair("api-version", API_VERSION)
            .append_pair("resource", resource);

        let mut req = Request::new(url.clone(), Method::Get);
        req.insert_header(HEADER_METADATA, "true");

        let rsp = self.http_client.execute_request(&req).await?;
        let (status, headers, body) = rsp.deconstruct();
        let bytes = body.collect().await?;

        if status != StatusCode::Unauthorized {
            // If it's already success, treat as protocol error because Arc expects 401 first.
            if status.is_success() {
                return Err(Error::message(
                    ErrorKind::Credential,
                    format!("Azure Arc challenge expected HTTP 401, received {}", status),
                ));
            }
            return Err(http_response_from_body(status, &bytes).into_error());
        }

        let www_auth = headers
            .get_str(&azure_core::http::headers::HeaderName::from_static(
                HEADER_WWW_AUTHENTICATE,
            ))
            .map_err(|_| {
                Error::message(
                    ErrorKind::Credential,
                    "Azure Arc response missing www-authenticate header",
                )
            })?;

        // Extract path after "Basic realm="
        let secret_path = parse_basic_realm_path(www_auth).ok_or_else(|| {
            Error::message(
                ErrorKind::Credential,
                "Azure Arc www-authenticate header missing expected Basic realm path",
            )
        })?;

        validate_arc_secret_path(
            &secret_path,
            self.tokens_dir()
                .as_deref()
                .unwrap_or("<unavailable default tokens dir>"),
        )?;

        let secret = fs::read(&secret_path).with_context(ErrorKind::Credential, || {
            format!("Azure Arc failed to read secret file '{}'", secret_path)
        })?;

        if secret.len() as u64 > ARC_MAX_FILE_SIZE {
            return Err(Error::message(
                ErrorKind::Credential,
                format!(
                    "Azure Arc secret file too large ({} bytes, max {})",
                    secret.len(),
                    ARC_MAX_FILE_SIZE
                ),
            ));
        }

        // Phase 2: authorized request
        let url2 = url;
        // same query already present
        let mut req2 = Request::new(url2, Method::Get);
        req2.insert_header(HEADER_METADATA, "true");
        req2.insert_header(
            HEADER_AUTHORIZATION,
            format!("Basic {}", String::from_utf8_lossy(&secret)),
        );

        let rsp2 = self.http_client.execute_request(&req2).await?;
        let (status2, _, body2) = rsp2.deconstruct();
        let body2 = body2.collect().await?;
        if !status2.is_success() {
            return Err(http_response_from_body(status2, &body2).into_error());
        }

        let token_response: ArcTokenResponse = from_json(&body2)
            .with_context(ErrorKind::Credential, || {
                "Azure Arc token response invalid JSON".to_string()
            })?;

        Ok(AccessToken::new(
            token_response.access_token,
            token_response.expires_on,
        ))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for AzureArcManagedIdentityCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, options, |s, o| self.get_token_impl(s, o))
            .await
    }
}

fn parse_basic_realm_path(header: &str) -> Option<String> {
    // Expect pattern containing 'Basic realm=' then path
    let lower = header.to_lowercase();
    let idx = lower.find("basic realm=")?;
    let after = &header[idx + "Basic realm=".len()..];
    // Path ends at first whitespace or is full remainder
    let trimmed = after.trim();
    // Remove any surrounding quotes if present
    let path = trimmed
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string();
    Some(path)
}

fn validate_arc_secret_path(path_str: &str, expected_dir: &str) -> azure_core::Result<()> {
    let path = Path::new(path_str);

    if path.extension().and_then(|e| e.to_str()) != Some(&ARC_FILE_EXTENSION[1..]) {
        return Err(Error::message(
            ErrorKind::Credential,
            format!(
                "Azure Arc secret file must have {} extension",
                ARC_FILE_EXTENSION
            ),
        ));
    }

    if !path.exists() {
        return Err(Error::message(
            ErrorKind::Credential,
            "Azure Arc secret file does not exist",
        ));
    }

    // Directory validation (best-effort)
    if let Some(parent) = path.parent() {
        if parent.to_string_lossy() != expected_dir {
            // Soft validation: don't fail outright if override var provided
            if std::env::var(ARC_TOKENS_DIR_OVERRIDE).is_err() {
                return Err(Error::message(
                    ErrorKind::Credential,
                    format!(
                        "Azure Arc secret file directory mismatch (expected {}, got {})",
                        expected_dir,
                        parent.to_string_lossy()
                    ),
                ));
            }
        }
    }

    Ok(())
}

// Same expires_on parsing logic used by IMDS (string unix epoch)
fn expires_on_string<'de, D>(deserializer: D) -> std::result::Result<OffsetDateTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = String::deserialize(deserializer)?;
    let as_i64 = v.parse::<i64>().map_err(serde::de::Error::custom)?;
    OffsetDateTime::from_unix_timestamp(as_i64).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
struct ArcTokenResponse {
    pub access_token: Secret,
    #[serde(deserialize_with = "expires_on_string")]
    pub expires_on: OffsetDateTime,
    pub token_type: String,
    pub resource: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::{
        http::{
            headers::{HeaderName, Headers},
            RawResponse,
        },
        Bytes,
    };
    use azure_core_test::http::MockHttpClient;
    use futures::FutureExt;
    use std::{
        io::Write,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    #[tokio::test]
    async fn arc_challenge_flow() {
        // Prepare temp tokens dir and secret file (avoid external tempfile crate)
        let base_dir = {
            let p = std::env::temp_dir().join(format!(
                "arc_test_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).unwrap();
            p
        };
        let secret_path = base_dir.join("secret.key");
        let mut f = std::fs::File::create(&secret_path).unwrap();
        write!(f, "arc-secret").unwrap();

        // Build environment
        let env = {
            let override_dir = base_dir.to_string_lossy().into_owned();
            let pairs = vec![
                (
                    "IDENTITY_ENDPOINT",
                    "http://localhost:40342/metadata/identity/oauth2/token",
                ),
                ("IMDS_ENDPOINT", "present"),
                (super::ARC_TOKENS_DIR_OVERRIDE, override_dir.as_str()),
            ];
            Env::from(&pairs[..])
        };

        let expires_on = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        // First 401 with challenge
        let mut h1 = Headers::default();
        let header_value = format!("Basic realm={}", secret_path.to_string_lossy());
        // Leak the boxed string to obtain a 'static str for test header insertion (test-only)
        let header_value_static: &'static str = Box::leak(header_value.into_boxed_str());
        h1.insert(
            HeaderName::from_static(HEADER_WWW_AUTHENTICATE),
            header_value_static,
        );
        let resp1 = RawResponse::from_bytes(StatusCode::Unauthorized, h1, Bytes::from_static(b""));

        // Second 200 success
        let body2 = format!(
            r#"{{"access_token":"*","expires_on":"{}","token_type":"Bearer","resource":"https://management.azure.com"}}"#,
            expires_on
        );
        let resp2 = RawResponse::from_bytes(StatusCode::Ok, Headers::default(), Bytes::from(body2));

        let responses = Arc::new(Mutex::new(vec![resp1, resp2]));
        let count = Arc::new(AtomicUsize::new(0));
        let responses_c = responses.clone();
        let count_c = count.clone();
        let mock = MockHttpClient::new(move |_req| {
            let responses_c2 = responses_c.clone();
            let count_c2 = count_c.clone();
            async move {
                count_c2.fetch_add(1, Ordering::SeqCst);
                let mut v = responses_c2.lock().unwrap();
                Ok(v.remove(0))
            }
            .boxed()
        });

        let options = TokenCredentialOptions {
            http_client: Arc::new(mock),
            env,
            ..Default::default()
        };

        let cred = AzureArcManagedIdentityCredential::new(options).unwrap();
        let token = cred
            .get_token(&["https://management.azure.com/.default"], None)
            .await
            .unwrap();
        assert_eq!(token.token.secret(), "*");
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // Cache hit
        let token2 = cred
            .get_token(&["https://management.azure.com/.default"], None)
            .await
            .unwrap();
        assert_eq!(token2.token.secret(), "*");
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn arc_missing_header() {
        let base_dir = {
            let p = std::env::temp_dir().join(format!(
                "arc_test_missing_hdr_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).unwrap();
            p
        };

        let env = {
            let override_dir = base_dir.to_string_lossy().into_owned();
            let pairs = vec![
                (
                    "IDENTITY_ENDPOINT",
                    "http://localhost:40342/metadata/identity/oauth2/token",
                ),
                ("IMDS_ENDPOINT", "present"),
                (super::ARC_TOKENS_DIR_OVERRIDE, override_dir.as_str()),
            ];
            Env::from(&pairs[..])
        };

        // 401 without www-authenticate header
        let resp1 = RawResponse::from_bytes(
            StatusCode::Unauthorized,
            Headers::default(),
            Bytes::from_static(b""),
        );

        let responses = Arc::new(Mutex::new(vec![resp1]));
        let count = Arc::new(AtomicUsize::new(0));
        let responses_c = responses.clone();
        let count_c = count.clone();
        let mock = MockHttpClient::new(move |_req| {
            let responses_c2 = responses_c.clone();
            let count_c2 = count_c.clone();
            async move {
                count_c2.fetch_add(1, Ordering::SeqCst);
                let mut v = responses_c2.lock().unwrap();
                Ok(v.remove(0))
            }
            .boxed()
        });

        let options = TokenCredentialOptions {
            http_client: Arc::new(mock),
            env,
            ..Default::default()
        };
        let cred = AzureArcManagedIdentityCredential::new(options).unwrap();
        let err = cred
            .get_token(&["https://management.azure.com/.default"], None)
            .await
            .err()
            .expect("expected error for missing header");
        assert!(
            err.to_string().contains("missing www-authenticate"),
            "unexpected error: {err}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn arc_secret_bad_extension() {
        let base_dir = {
            let p = std::env::temp_dir().join(format!(
                "arc_test_bad_ext_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).unwrap();
            p
        };
        let secret_path = base_dir.join("secret.txt");
        let mut f = std::fs::File::create(&secret_path).unwrap();
        write!(f, "ignored").unwrap();

        let env = {
            let override_dir = base_dir.to_string_lossy().into_owned();
            let pairs = vec![
                (
                    "IDENTITY_ENDPOINT",
                    "http://localhost:40342/metadata/identity/oauth2/token",
                ),
                ("IMDS_ENDPOINT", "present"),
                (super::ARC_TOKENS_DIR_OVERRIDE, override_dir.as_str()),
            ];
            Env::from(&pairs[..])
        };

        let mut h1 = Headers::default();
        let header_value = format!("Basic realm={}", secret_path.to_string_lossy());
        let header_value_static: &'static str = Box::leak(header_value.into_boxed_str());
        h1.insert(
            HeaderName::from_static(HEADER_WWW_AUTHENTICATE),
            header_value_static,
        );
        let resp1 = RawResponse::from_bytes(StatusCode::Unauthorized, h1, Bytes::from_static(b""));

        let responses = Arc::new(Mutex::new(vec![resp1]));
        let count = Arc::new(AtomicUsize::new(0));
        let responses_c = responses.clone();
        let count_c = count.clone();
        let mock = MockHttpClient::new(move |_req| {
            let responses_c2 = responses_c.clone();
            let count_c2 = count_c.clone();
            async move {
                count_c2.fetch_add(1, Ordering::SeqCst);
                let mut v = responses_c2.lock().unwrap();
                Ok(v.remove(0))
            }
            .boxed()
        });

        let options = TokenCredentialOptions {
            http_client: Arc::new(mock),
            env,
            ..Default::default()
        };
        let cred = AzureArcManagedIdentityCredential::new(options).unwrap();
        let err = cred
            .get_token(&["https://management.azure.com/.default"], None)
            .await
            .err()
            .expect("expected error for bad extension");
        assert!(
            err.to_string().contains("must have .key extension"),
            "unexpected error: {err}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn arc_secret_too_large() {
        let base_dir = {
            let p = std::env::temp_dir().join(format!(
                "arc_test_large_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).unwrap();
            p
        };
        let secret_path = base_dir.join("secret.key");
        {
            let mut f = std::fs::File::create(&secret_path).unwrap();
            // Write > 4096 bytes
            let large = vec![b'a'; (super::ARC_MAX_FILE_SIZE + 10) as usize];
            f.write_all(&large).unwrap();
        }

        let env = {
            let override_dir = base_dir.to_string_lossy().into_owned();
            let pairs = vec![
                (
                    "IDENTITY_ENDPOINT",
                    "http://localhost:40342/metadata/identity/oauth2/token",
                ),
                ("IMDS_ENDPOINT", "present"),
                (super::ARC_TOKENS_DIR_OVERRIDE, override_dir.as_str()),
            ];
            Env::from(&pairs[..])
        };

        let mut h1 = Headers::default();
        let header_value = format!("Basic realm={}", secret_path.to_string_lossy());
        let header_value_static: &'static str = Box::leak(header_value.into_boxed_str());
        h1.insert(
            HeaderName::from_static(HEADER_WWW_AUTHENTICATE),
            header_value_static,
        );
        let resp1 = RawResponse::from_bytes(StatusCode::Unauthorized, h1, Bytes::from_static(b""));

        let responses = Arc::new(Mutex::new(vec![resp1]));
        let count = Arc::new(AtomicUsize::new(0));
        let responses_c = responses.clone();
        let count_c = count.clone();
        let mock = MockHttpClient::new(move |_req| {
            let responses_c2 = responses_c.clone();
            let count_c2 = count_c.clone();
            async move {
                count_c2.fetch_add(1, Ordering::SeqCst);
                let mut v = responses_c2.lock().unwrap();
                Ok(v.remove(0))
            }
            .boxed()
        });

        let options = TokenCredentialOptions {
            http_client: Arc::new(mock),
            env,
            ..Default::default()
        };
        let cred = AzureArcManagedIdentityCredential::new(options).unwrap();
        let err = cred
            .get_token(&["https://management.azure.com/.default"], None)
            .await
            .err()
            .expect("expected error for oversized secret");
        assert!(
            err.to_string().contains("secret file too large"),
            "unexpected error: {err}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
