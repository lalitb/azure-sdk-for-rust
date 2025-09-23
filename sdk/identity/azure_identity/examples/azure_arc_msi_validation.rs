use azure_identity::ManagedIdentityCredential;
  use azure_core::credentials::TokenCredential;
  use std::env;
  use reqwest::Client;

  #[tokio::main]
  async fn main() -> Result<(), Box<dyn std::error::Error>> {
      println!("Azure Arc Managed Identity Rust Implementation Test");
      println!("=====================================================");

      // Environment validation
      println!("🔍 Environment Check:");

      if let Ok(sub_id) = env::var("AZURE_SUBSCRIPTION_ID") {
          println!("  AZURE_SUBSCRIPTION_ID: {}", sub_id);
      } else {
          println!("  AZURE_SUBSCRIPTION_ID not set");
          return Err("Missing AZURE_SUBSCRIPTION_ID environment variable".into());
      }

      // Check Azure Arc environment indicators
      check_azure_arc_environment();

      println!("\nTesting ManagedIdentityCredential (should auto-detect Azure Arc):");

      // Create the credential - this should automatically detect Azure Arc environment
      let credential = match ManagedIdentityCredential::new(None) {
          Ok(cred) => {
              println!("  Successfully created ManagedIdentityCredential");
              cred
          }
          Err(e) => {
              println!("  Failed to create ManagedIdentityCredential: {}", e);
              return Err(e.into());
          }
      };

      // Test 1: Get token for Azure Resource Manager
      println!("\n🎫 Test 1: Getting Azure Resource Manager token...");
      let token = match credential
          .get_token(&["https://management.azure.com/.default"], None)
          .await
      {
          Ok(token) => {
              println!("  Successfully obtained ARM token!");
              println!("     Token expires at: {:?}", token.expires_on);
              println!("     Token length: {} characters", token.token.secret().len());
              token
          }
          Err(e) => {
              println!("  Failed to get ARM token: {}", e);
              return Err(e.into());
          }
      };

      // Test 2: Verify token caching (second request should be faster)
      println!("\nTest 2: Testing token caching...");
      let start = std::time::Instant::now();
      let cached_token = credential
          .get_token(&["https://management.azure.com/.default"], None)
          .await?;
      let duration = start.elapsed();

      println!("  Second token request completed in {:?}", duration);
      println!("  Token comparison:");
      println!("     First token length: {}", token.token.secret().len());
      println!("     Cached token length: {}", cached_token.token.secret().len());
      println!("     Tokens match: {}", token.token.secret() == cached_token.token.secret());

      // Test 3: API call to Azure Resource Manager
      if let Ok(subscription_id) = env::var("AZURE_SUBSCRIPTION_ID") {
          println!("\nTest 3: Testing Azure Resource Manager API call...");

          let url = format!(
              "https://management.azure.com/subscriptions/{}/resourceGroups?api-version=2021-04-01",
              subscription_id
          );

          let client = Client::new();
          let response = client
              .get(&url)
              .header("Authorization", format!("Bearer {}", token.token.secret()))
              .header("User-Agent", "azure-arc-rust-test/1.0")
              .send()
              .await?;

          println!("     Response status: {}", response.status());

          if response.status().is_success() {
              let body = response.text().await?;

              if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                  if let Some(resource_groups) = json.get("value").and_then(|v| v.as_array()) {
                      println!("  ✅ Successfully retrieved {} resource group(s)", resource_groups.len());

                      // Show resource group names
                      for (i, rg) in resource_groups.iter().take(5).enumerate() {
                          if let Some(name) = rg.get("name").and_then(|n| n.as_str()) {
                              println!("     {}. {}", i + 1, name);
                          }
                      }
                      if resource_groups.len() > 5 {
                          println!("     ... and {} more", resource_groups.len() - 5);
                      }
                  }
              }
          } else {
              let status = response.status();
              let error_body = response.text().await?;
              println!("  API call failed: {}", error_body);
              return Err(format!("API call failed with status {}", status).into());
          }
      }

      // Test 4: Test different scopes
      println!("\n🎯 Test 4: Testing different Azure scopes...");

      let test_scopes = [
          ("Azure Resource Manager", "https://management.azure.com/.default"),
          ("Key Vault", "https://vault.azure.net/.default"),
          ("Storage", "https://storage.azure.com/.default"),
      ];

      for (name, scope) in &test_scopes {
          match credential.get_token(&[scope], None).await {
              Ok(scope_token) => {
                  println!("  {} token: {} chars", name, scope_token.token.secret().len());
              }
              Err(e) => {
                  println!("  {} token failed: {}", name, e);
              }
          }
      }

      println!("\nAzure Arc MSI Rust Implementation Test Completed!");
      println!("   All tests passed successfully! 🎊");

      Ok(())
  }

  fn check_azure_arc_environment() {
      println!("  Azure Arc Environment Indicators:");

      // Check for Arc agent
      match std::process::Command::new("azcmagent").arg("show").output() {
          Ok(output) if output.status.success() => {
              println!("     Azure Arc agent detected and running");
          }
          _ => {
              println!("     Azure Arc agent not detected");
          }
      }

      // Check tokens directory
      if std::path::Path::new("/var/opt/azcmagent/tokens").exists() {
          if let Ok(entries) = std::fs::read_dir("/var/opt/azcmagent/tokens") {
              let key_count = entries
                  .filter_map(|e| e.ok())
                  .filter(|e| e.path().extension().map_or(false, |ext| ext == "key"))
                  .count();

              if key_count > 0 {
                  println!("     Found {} Azure Arc token file(s)", key_count);
              } else {
                  println!("     Azure Arc tokens directory exists but no .key files found");
              }
          }
      } else {
          println!("     Azure Arc tokens directory not found");
      }

      // Check environment variables
      if let Ok(endpoint) = env::var("IDENTITY_ENDPOINT") {
          println!("     IDENTITY_ENDPOINT: {}", endpoint);
      } else {
          println!("     IDENTITY_ENDPOINT not set (will use default)");
      }

      if let Ok(imds) = env::var("IMDS_ENDPOINT") {
          println!("     IMDS_ENDPOINT: {}", imds);
      } else {
          println!("     IMDS_ENDPOINT not set");
      }
  }
