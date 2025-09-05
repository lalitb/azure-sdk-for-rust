// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
 Sequence flow for Azure Arc Managed Identity:

 Caller -> Credential: get_token(scopes)
 Credential -> Cache: check for cached token
 alt valid cached token
     Cache -> Credential: return token
     Credential -> Caller: token
 else expired/missing
     Credential -> Arc Endpoint: GET (metadata:true)
     Arc Endpoint -> Credential: 401 + WWW-Authenticate: file path
     Credential -> File System: read(challenge token)
     File System -> Credential: challenge token
     Credential -> Arc Endpoint: GET (metadata:true, authorization: Basic {token})
     Arc Endpoint -> Credential: 200 + {access_token, expires_on}
     Credential -> Cache: store token
     Credential -> Caller: token
 end
*/

use crate::{ImdsId, TokenCredentialOptions};
use async_lock::Mutex;
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::error::{ErrorKind, ResultExt};
use azure_core::http::{headers::HeaderName, Method, Request, StatusCode, Url};
use azure_core::sleep;
use std::fs;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const ENDPOINT_ENV: &str = "IDENTITY_ENDPOINT";
const IMDS_ENDPOINT_ENV: &str = "IMDS_ENDPOINT";
const API_VERSION: &str = "2019-11-01";
const METADATA_HEADER: HeaderName = HeaderName::from_static("metadata");
const AUTHORIZATION_HEADER: HeaderName = HeaderName::from_static("authorization");
const WWW_AUTHENTICATE_HEADER: HeaderName = HeaderName::from_static("www-authenticate");
const DEFAULT_ENDPOINT: &str = "http://localhost:40342/metadata/identity/oauth2/token";
const RETRY_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 1000;

/// Authenticates using Azure Arc managed identity.
///
/// Azure Arc-enabled servers use a challenge-response authentication mechanism.
/// The authentication flow involves:
/// 1. Making an initial request to get a challenge token file path
/// 2. Reading the challenge token from the file system
/// 3. Making the actual token request with the challenge token
///
/// ## Environment Variables Required
/// - `IDENTITY_ENDPOINT`: The Azure Arc managed identity endpoint (defaults to http://localhost:40342/...)
/// - `IMDS_ENDPOINT`: The IMDS endpoint for Azure Arc (must be set to distinguish from other environments)
///
/// ## Reference
/// See [Azure Arc managed identity documentation](https://learn.microsoft.com/azure/azure-arc/servers/managed-identity-authentication)
#[derive(Debug)]
/// Azure Arc Managed Identity credential.
///
/// Performs the challenge-response flow:
/// 1. Initial unauthenticated GET -> 401 with `WWW-Authenticate: Basic realm=/path/to/file`
/// 2. Read challenge file contents (expected small key, max 4096 bytes)
/// 3. Retry GET with `Authorization: Basic <file contents>` to obtain token.
///
/// Required environment variables:
/// - IMDS_ENDPOINT (its presence triggers Azure Arc detection)
/// - Optional IDENTITY_ENDPOINT (falls back to default Arc endpoint if missing)
///
/// User-assigned identity is supported via `ImdsId::ClientId(..)`.
pub struct AzureArcManagedIdentityCredential {
    endpoint: Url,
    id: ImdsId,
    options: TokenCredentialOptions,
    cached_token: Mutex<Option<(AccessToken, std::time::Instant)>>,
}

impl AzureArcManagedIdentityCredential {
    /// Creates a new Azure Arc managed identity credential.
    ///
    /// # Arguments
    /// * `id` - The managed identity to authenticate (system or user-assigned)
    /// * `options` - Token credential options for HTTP client, etc.
    ///
    /// # Returns
    /// Returns a Result containing the credential or an error if required environment
    /// variables are missing or invalid.
    ///
    /// # Errors
    /// - If `IMDS_ENDPOINT` environment variable is not set (required to identify Arc environment)
    /// - If `IDENTITY_ENDPOINT` is set but not a valid URL
    pub fn new(
        id: ImdsId,
        options: impl Into<TokenCredentialOptions>,
    ) -> azure_core::Result<Arc<Self>> {
        let options = options.into();
        let env = options.env();

        // IMDS_ENDPOINT must be set to distinguish Arc from other environments
        env.var(IMDS_ENDPOINT_ENV)
            .with_context(ErrorKind::Credential, || {
                format!(
                    "Azure Arc managed identity requires {} environment variable to be set",
                    IMDS_ENDPOINT_ENV
                )
            })?;

        // Use IDENTITY_ENDPOINT if set, otherwise use default Arc endpoint
        let endpoint = env
            .var(ENDPOINT_ENV)
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());

        let endpoint = Url::parse(&endpoint).with_context(ErrorKind::Credential, || {
            format!("Azure Arc managed identity endpoint must be a valid URL, but is '{endpoint}'")
        })?;

        Ok(Arc::new(Self {
            endpoint,
            id,
            options,
            cached_token: Mutex::new(None),
        }))
    }

    /// Performs the Azure Arc challenge-response authentication flow.
    ///
    /// This involves:
    /// 1. Making an initial request to get a WWW-Authenticate header with challenge file path
    /// 2. Reading the challenge token from the specified file
    /// 3. Making the actual token request with the challenge token
    async fn get_challenge_token(&self, resource: &str) -> azure_core::Result<String> {
        let http_client = self.options.http_client();

        // Build the initial request URL
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .extend_pairs([("api-version", API_VERSION), ("resource", resource)]);

        // Add client_id for user-assigned identities
        if let ImdsId::ClientId(client_id) = &self.id {
            url.query_pairs_mut().append_pair("client_id", client_id);
        }

        for attempt in 0..RETRY_ATTEMPTS {
            // Step 1: Make initial request to get challenge file path
            let mut request = Request::new(url.clone(), Method::Get);
            request.insert_header(METADATA_HEADER.clone(), "true");

            let response = http_client.execute_request(&request).await?;

            // Check if we got a WWW-Authenticate header with the challenge file path
            if response.status() == StatusCode::Unauthorized {
                if let Ok(www_auth) = response.headers().get_str(&WWW_AUTHENTICATE_HEADER) {
                    // Parse "Basic realm=/path/to/challenge/file"
                    if let Some(realm_start) = www_auth.find("Basic realm=") {
                        let file_path = &www_auth[realm_start + "Basic realm=".len()..];

                        // Step 2: Read challenge token from file
                        match fs::read_to_string(file_path.trim()) {
                            Ok(challenge_token) => return Ok(challenge_token.trim().to_string()),
                            Err(e) => {
                                if attempt == RETRY_ATTEMPTS - 1 {
                                    return Err(azure_core::Error::new(
                                        ErrorKind::Credential,
                                        format!("Failed to read Azure Arc challenge token from '{}': {}", file_path, e)
                                    ));
                                }
                                // Retry on file read failure (file might not be ready yet)
                                sleep(Duration::milliseconds(RETRY_DELAY_MS as i64)).await;
                                continue;
                            }
                        }
                    }
                }
            }

            // If we didn't get the expected challenge response, return error
            if attempt == RETRY_ATTEMPTS - 1 {
                let status = response.status();
                let body = response
                    .into_body()
                    .collect_string()
                    .await
                    .unwrap_or_default();
                return Err(azure_core::Error::new(
                    ErrorKind::Credential,
                    format!(
                        "Azure Arc challenge request failed. Expected WWW-Authenticate header with challenge file path. Status: {}, Body: {}",
                        status, body
                    )
                ));
            }

            sleep(Duration::milliseconds(RETRY_DELAY_MS as i64)).await;
        }

        unreachable!()
    }

    /// Makes the actual token request using the challenge token.
    async fn request_token_with_challenge(
        &self,
        resource: &str,
        challenge_token: &str,
    ) -> azure_core::Result<AccessToken> {
        let http_client = self.options.http_client();

        // Build the request URL
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .extend_pairs([("api-version", API_VERSION), ("resource", resource)]);

        // Add client_id for user-assigned identities
        if let ImdsId::ClientId(client_id) = &self.id {
            url.query_pairs_mut().append_pair("client_id", client_id);
        }

        // Step 3: Make token request with challenge token
        let mut request = Request::new(url, Method::Get);
        request.insert_header(METADATA_HEADER.clone(), "true");
        request.insert_header(
            AUTHORIZATION_HEADER.clone(),
            format!("Basic {}", challenge_token),
        );

        let response = http_client.execute_request(&request).await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .into_body()
                .collect_string()
                .await
                .unwrap_or_default();
            return Err(azure_core::Error::new(
                ErrorKind::Credential,
                format!(
                    "Azure Arc token request failed. Status: {}, Body: {}",
                    status, body
                ),
            ));
        }

        // Parse the token response
        let body = response.into_body().collect_string().await?;
        let token_response: serde_json::Value = serde_json::from_str(&body)
            .with_context(ErrorKind::Credential, || {
                format!("Failed to parse Azure Arc token response: {}", body)
            })?;

        let access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| {
                azure_core::Error::new(
                    ErrorKind::Credential,
                    "Azure Arc token response missing 'access_token' field",
                )
            })?
            .to_string();

        // Parse expires_on (Unix timestamp)
        let expires_on = if let Some(expires_on_str) = token_response["expires_on"].as_str() {
            expires_on_str
                .parse::<i64>()
                .with_context(ErrorKind::Credential, || {
                    format!("Failed to parse expires_on timestamp: {}", expires_on_str)
                })?
        } else if let Some(expires_on_num) = token_response["expires_on"].as_i64() {
            expires_on_num
        } else {
            return Err(azure_core::Error::new(
                ErrorKind::Credential,
                "Azure Arc token response missing or invalid 'expires_on' field",
            ));
        };

        let expires_on = OffsetDateTime::from_unix_timestamp(expires_on)
            .with_context(ErrorKind::Credential, || {
                format!("Invalid expires_on timestamp: {}", expires_on)
            })?;

        Ok(AccessToken::new(access_token, expires_on))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for AzureArcManagedIdentityCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        // Convert scopes to resource (take first scope and remove /.default suffix)
        let resource = if scopes.is_empty() {
            "https://management.azure.com/"
        } else {
            let scope = scopes[0];
            if scope.ends_with("/.default") {
                &scope[..scope.len() - 10] // Remove "/.default"
            } else {
                scope
            }
        };

        // Check cached token first
        {
            let cached = self.cached_token.lock().await;
            if let Some((token, _cached_at)) = cached.as_ref() {
                // Use token if it expires in more than 5 minutes
                let expires_in =
                    token.expires_on.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp();
                if expires_in > 300 {
                    return Ok(token.clone());
                }
            }
        }

        // Get challenge token and request new access token
        let challenge_token = self.get_challenge_token(resource).await?;
        let access_token = self
            .request_token_with_challenge(resource, &challenge_token)
            .await?;

        // Cache the token
        {
            let mut cached = self.cached_token.lock().await;
            *cached = Some((access_token.clone(), std::time::Instant::now()));
        }

        Ok(access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::Env, tests::*};
    use azure_core::{
        http::{
            headers::{HeaderName, Headers},
            Method, RawResponse, StatusCode, Url,
        },
        Bytes,
    };
    use azure_core_test::http::MockHttpClient;
    use std::io::Write;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn azure_arc_system_assigned() {
        let endpoint = "http://localhost:40342/metadata/identity/oauth2/token";
        let challenge_token = "challenge-token-content";

        // Create a temporary file for the challenge token
        let challenge_file = NamedTempFile::new().unwrap();
        writeln!(&challenge_file, "{}", challenge_token).unwrap();
        let challenge_file_path = challenge_file.path().to_string_lossy().to_string();

        let expires_on = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        let mock_client = MockHttpClient::new(move |req| {
            let request_count = request_count_clone.clone();
            let challenge_file_path = challenge_file_path.clone();
            let expected_endpoint = endpoint;
            let expected_challenge = challenge_token;

            Box::pin(async move {
                let count = request_count.fetch_add(1, Ordering::SeqCst);

                // Verify the request
                assert_eq!(req.method(), Method::Get);

                let mut expected_url = Url::parse(expected_endpoint).unwrap();
                expected_url.query_pairs_mut().extend_pairs([
                    ("api-version", API_VERSION),
                    ("resource", LIVE_TEST_RESOURCE),
                ]);

                let mut req_url = req.url().clone();
                req_url.set_query(None);
                expected_url.set_query(None);
                assert_eq!(req_url, expected_url);

                // Check required headers
                assert_eq!(
                    req.headers()
                        .get_str(&HeaderName::from_static("metadata"))
                        .unwrap(),
                    "true"
                );

                if count == 0 {
                    // First request: return challenge response
                    assert!(req
                        .headers()
                        .get_str(&HeaderName::from_static("authorization"))
                        .is_err());

                    let mut headers = Headers::new();
                    headers.insert(
                        WWW_AUTHENTICATE_HEADER.clone(),
                        format!("Basic realm={}", challenge_file_path),
                    );

                    Ok(RawResponse::from_bytes(
                        StatusCode::Unauthorized,
                        headers,
                        Bytes::new(),
                    ))
                } else {
                    // Second request: return token
                    assert_eq!(
                        req.headers()
                            .get_str(&HeaderName::from_static("authorization"))
                            .unwrap(),
                        format!("Basic {}", expected_challenge)
                    );

                    Ok(RawResponse::from_bytes(
                        StatusCode::Ok,
                        Headers::default(),
                        Bytes::from(format!(
                            r#"{{"access_token":"test-token","expires_on":"{}","resource":"{}","token_type":"Bearer"}}"#,
                            expires_on, LIVE_TEST_RESOURCE
                        )),
                    ))
                }
            })
        });

        let credential = AzureArcManagedIdentityCredential::new(
            ImdsId::SystemAssigned,
            TokenCredentialOptions {
                env: Env::from(
                    &[
                        (ENDPOINT_ENV, endpoint),
                        (IMDS_ENDPOINT_ENV, "http://localhost:40342"),
                    ][..],
                ),
                http_client: Arc::new(mock_client),
                ..Default::default()
            },
        )
        .expect("valid credential");

        // Test token retrieval
        let token = credential
            .get_token(LIVE_TEST_SCOPES, None)
            .await
            .expect("token");

        assert_eq!(token.token.secret(), "test-token");
        assert_eq!(token.expires_on.unix_timestamp(), expires_on as i64);
        assert_eq!(request_count.load(Ordering::SeqCst), 2); // Challenge + token request

        // Test token caching
        let token2 = credential
            .get_token(LIVE_TEST_SCOPES, None)
            .await
            .expect("cached token");

        assert_eq!(token2.token.secret(), "test-token");
        assert_eq!(request_count.load(Ordering::SeqCst), 2); // Should be cached

        // Keep challenge file alive until test is done
        drop(challenge_file);
    }

    #[tokio::test]
    async fn azure_arc_user_assigned() {
        let endpoint = "http://localhost:40342/metadata/identity/oauth2/token";
        let challenge_token = "user-challenge-token";
        let client_id = "test-client-id";

        // Create a temporary file for the challenge token
        let challenge_file = NamedTempFile::new().unwrap();
        writeln!(&challenge_file, "{}", challenge_token).unwrap();
        let challenge_file_path = challenge_file.path().to_string_lossy().to_string();

        let expires_on = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        let mock_client = MockHttpClient::new(move |req| {
            let request_count = request_count_clone.clone();
            let challenge_file_path = challenge_file_path.clone();
            let expected_client_id = client_id;
            let expected_challenge = challenge_token;

            Box::pin(async move {
                let count = request_count.fetch_add(1, Ordering::SeqCst);

                // Verify client_id is in query parameters for both requests
                let query_pairs: std::collections::HashMap<String, String> =
                    req.url().query_pairs().into_owned().collect();
                assert_eq!(query_pairs.get("client_id").unwrap(), expected_client_id);

                if count == 0 {
                    // First request: return challenge response
                    let mut headers = Headers::new();
                    headers.insert(
                        WWW_AUTHENTICATE_HEADER.clone(),
                        format!("Basic realm={}", challenge_file_path),
                    );

                    Ok(RawResponse::from_bytes(
                        StatusCode::Unauthorized,
                        headers,
                        Bytes::new(),
                    ))
                } else {
                    // Second request: return token with challenge auth
                    assert_eq!(
                        req.headers()
                            .get_str(&HeaderName::from_static("authorization"))
                            .unwrap(),
                        format!("Basic {}", expected_challenge)
                    );

                    Ok(RawResponse::from_bytes(
                        StatusCode::Ok,
                        Headers::default(),
                        Bytes::from(format!(
                            r#"{{"access_token":"user-token","expires_on":"{}","resource":"{}","token_type":"Bearer"}}"#,
                            expires_on, LIVE_TEST_RESOURCE
                        )),
                    ))
                }
            })
        });

        let credential = AzureArcManagedIdentityCredential::new(
            ImdsId::ClientId(client_id.to_string()),
            TokenCredentialOptions {
                env: Env::from(
                    &[
                        (ENDPOINT_ENV, endpoint),
                        (IMDS_ENDPOINT_ENV, "http://localhost:40342"),
                    ][..],
                ),
                http_client: Arc::new(mock_client),
                ..Default::default()
            },
        )
        .expect("valid credential");

        let token = credential
            .get_token(LIVE_TEST_SCOPES, None)
            .await
            .expect("token");

        assert_eq!(token.token.secret(), "user-token");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        // Keep challenge file alive until test is done
        drop(challenge_file);
    }

    #[test]
    fn uses_default_endpoint_when_identity_endpoint_not_set() {
        let result = AzureArcManagedIdentityCredential::new(
            ImdsId::SystemAssigned,
            TokenCredentialOptions {
                env: Env::from(&[(IMDS_ENDPOINT_ENV, "http://localhost:40342")][..]),
                ..Default::default()
            },
        );

        assert!(result.is_ok());
        let credential = result.unwrap();
        assert_eq!(credential.endpoint.to_string(), DEFAULT_ENDPOINT);
    }

    #[test]
    fn missing_imds_endpoint() {
        let result = AzureArcManagedIdentityCredential::new(
            ImdsId::SystemAssigned,
            TokenCredentialOptions {
                env: Env::from(
                    &[(
                        ENDPOINT_ENV,
                        "http://localhost:40342/metadata/identity/oauth2/token",
                    )][..],
                ),
                ..Default::default()
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("IMDS_ENDPOINT"));
    }

    #[test]
    fn invalid_endpoint_url() {
        let result = AzureArcManagedIdentityCredential::new(
            ImdsId::SystemAssigned,
            TokenCredentialOptions {
                env: Env::from(
                    &[
                        (ENDPOINT_ENV, "not-a-valid-url"),
                        (IMDS_ENDPOINT_ENV, "http://localhost:40342"),
                    ][..],
                ),
                ..Default::default()
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("valid URL"));
    }
}
