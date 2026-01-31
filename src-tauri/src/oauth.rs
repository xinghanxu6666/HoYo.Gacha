use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::consts;
use crate::database::{self, Database, KvMut};

// OAuth client credentials and endpoints (edit here as requested)
pub const CLIENT_ID: &str = "a5ff2f57-81c8-444b-b531-a2ff47a56374";
pub const CLIENT_SECRET: &str = "4YLFObnlQf4bwYtRouzJBCXPmTxBU9sz";
pub const AUTHORIZE_ENDPOINT: &str = "https://pan.tx648.cn/session/authorize";
pub const TOKEN_ENDPOINT: &str = "https://pan.tx648.cn/api/v4/session/oauth/token";
pub const REFRESH_ENDPOINT: &str = "https://pan.tx648.cn/api/v4/session/token/refresh";
pub const USERINFO_ENDPOINT: &str = "https://pan.tx648.cn/api/v4/session/oauth/userinfo";
pub const REDIRECT_HOST: &str = "127.0.0.1";
pub const REDIRECT_PORT: u16 = 10033;
pub const REDIRECT_PATH: &str = "/callback";

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
  pub access_token: String,
  pub refresh_token: Option<String>,
  pub expires_in: Option<i64>,
  pub token_type: Option<String>,
  pub scope: Option<String>,
}

#[tauri::command]
pub async fn oauth_get_authorize_url(state: Option<String>) -> String {
  let redirect = format!("http://{}:{}{}", REDIRECT_HOST, REDIRECT_PORT, REDIRECT_PATH);
  // state if none, generate minimal timestamp state
  let state = state.unwrap_or_else(|| {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_secs().to_string())
      .unwrap_or_else(|_| "0".to_string())
  });

  let mut url = url::Url::parse(AUTHORIZE_ENDPOINT).unwrap_or_else(|_| url::Url::parse("https://example.invalid").unwrap());
  {
    let mut qp = url.query_pairs_mut();
    qp.append_pair("response_type", "code");
    qp.append_pair("client_id", CLIENT_ID);
    qp.append_pair("redirect_uri", &redirect);
    qp.append_pair("state", &state);
  }
  url.into_string()
}

// Listen on localhost:10033 for a single OAuth callback and exchange code for token
#[tauri::command]
pub async fn oauth_listen_for_callback(database: State<'_, Arc<Database>>) -> Result<TokenResponse, String> {
  // Bind to loopback
  let addr = format!("{}:{}", REDIRECT_HOST, REDIRECT_PORT);
  let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| format!("Bind error: {e}"))?;

  // Accept single connection
  let (mut socket, _) = listener.accept().await.map_err(|e| format!("Accept error: {e}"))?;

  // Read request until header end
  let mut buf = vec![0u8; 8192];
  let n = socket.read(&mut buf).await.map_err(|e| format!("Socket read error: {e}"))?;
  let req = String::from_utf8_lossy(&buf[..n]);
  // Parse request line
  let first_line = req.lines().next().ok_or("Invalid request")?;
  // Example: GET /callback?code=XXX&state=YYY HTTP/1.1
  let parts: Vec<&str> = first_line.split_whitespace().collect();
  if parts.len() < 2 {
    return Err("Invalid request line".into());
  }

  let path_and_q = parts[1];
  let url = url::Url::parse(&format!("http://localhost{}", path_and_q)).map_err(|e| format!("Url parse error: {e}"))?;
  let code = url.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()).ok_or("No code in callback")?;

  // Send simple HTTP response
  let body = "<html><body><h3>授权成功，可以关闭此窗口。</h3></body></html>";
  let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
  let _ = socket.write_all(resp.as_bytes()).await;

  // Exchange code for token
  let redirect = format!("http://{}:{}{}", REDIRECT_HOST, REDIRECT_PORT, REDIRECT_PATH);

  let params = [
    ("grant_type", "authorization_code"),
    ("code", &code),
    ("client_id", CLIENT_ID),
    ("client_secret", CLIENT_SECRET),
    ("redirect_uri", &redirect),
  ];

  let client = &*consts::REQWEST;
  let res = client
    .post(TOKEN_ENDPOINT)
    .form(&params)
    .send()
    .await
    .map_err(|e| format!("Token request error: {e}"))?;

  if !res.status().is_success() {
    let text = res.text().await.unwrap_or_default();
    return Err(format!("Token endpoint returned {}: {}", res.status(), text));
  }

  let token: TokenResponse = res.json().await.map_err(|e| format!("Parse token json error: {e}"))?;

  // Persist into database
  let db = database.inner();
  let kv = KvMut::from(db, consts::KV_PAN_OAUTH);
  kv.try_write_json(&token).await.map_err(|e| format!("DB write error: {e}"))?;

  Ok(token)
}

#[tauri::command]
pub async fn oauth_refresh_token(database: State<'_, Arc<Database>>) -> Result<TokenResponse, String> {
  // Read existing token
  let db = database.inner();
  let kv = KvMut::from(db, consts::KV_PAN_OAUTH);
  let current = kv.try_read_val_json::<TokenResponse>().await.map_err(|e| format!("DB read error: {e}"))?;
  let token = current.transpose().ok_or("No token stored")?;
  let refresh = token.refresh_token.clone().ok_or("No refresh token")?;

  let params = [
    ("grant_type", "refresh_token"),
    ("refresh_token", &refresh),
    ("client_id", CLIENT_ID),
    ("client_secret", CLIENT_SECRET),
  ];

  let client = &*consts::REQWEST;
  let res = client
    .post(REFRESH_ENDPOINT)
    .form(&params)
    .send()
    .await
    .map_err(|e| format!("Refresh request error: {e}"))?;

  if !res.status().is_success() {
    let text = res.text().await.unwrap_or_default();
    return Err(format!("Refresh endpoint returned {}: {}", res.status(), text));
  }

  let new_token: TokenResponse = res.json().await.map_err(|e| format!("Parse token json error: {e}"))?;
  let kv = KvMut::from(db, consts::KV_PAN_OAUTH);
  kv.try_write_json(&new_token).await.map_err(|e| format!("DB write error: {e}"))?;
  Ok(new_token)
}

#[tauri::command]
pub async fn oauth_upload_records(
  records: serde_json::Value,
  upload_url: String,
  database: State<'_, Arc<Database>>,
) -> Result<String, String> {
  // Read token
  let db = database.inner();
  let kv = KvMut::from(db, consts::KV_PAN_OAUTH);
  let current = kv.try_read_val_json::<TokenResponse>().await.map_err(|e| format!("DB read error: {e}"))?;
  let token = current.transpose().ok_or("No token stored")?;

  let client = &*consts::REQWEST;
  let bearer = format!("Bearer {}", token.access_token);

  let res = client
    .post(&upload_url)
    .header("Authorization", bearer)
    .header("Content-Type", "application/json")
    .body(serde_json::to_vec(&records).map_err(|e| format!("Serialize error: {e}"))?)
    .send()
    .await
    .map_err(|e| format!("Upload request error: {e}"))?;

  let status = res.status();
  let text = res.text().await.unwrap_or_default();
  if !status.is_success() {
    return Err(format!("Upload failed {}: {}", status, text));
  }

  Ok(text)
}

#[tauri::command]
pub async fn oauth_start_db_watcher(database: State<'_, Arc<Database>>) -> Result<(), String> {
  // Clone Arc<Database> for use inside watcher thread
  let db_arc = database.inner().clone();

  // Read stored upload URL once (must exist)
  let kv = KvMut::from(db_arc.as_ref(), consts::KV_PAN_UPLOAD_URL);
  let current = kv.try_read_val_json::<String>().await.map_err(|e| format!("DB read error: {e}"))?;
  let upload_url = current.transpose().ok_or("No upload_url stored")?;

  // Determine DB file path (same logic as Database::new)
  let db_path = if cfg!(debug_assertions) {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(consts::DATABASE)
  } else {
    std::env::current_exe()
      .expect("Failed to get current exe path")
      .parent()
      .unwrap()
      .join(consts::DATABASE)
  };

  // Use the current tokio handle to spawn async upload jobs from watcher thread
  let handle = tokio::runtime::Handle::current();

  std::thread::spawn(move || {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};

    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher: RecommendedWatcher = match RecommendedWatcher::new(move |res| {
      let _ = tx.send(res);
    }) {
      Ok(w) => w,
      Err(e) => {
        tracing::error!(message = "Failed to create watcher", ?e);
        return;
      }
    };

    if let Err(e) = watcher.watch(&db_path, RecursiveMode::NonRecursive) {
      tracing::error!(message = "Failed to watch db file", ?e);
      return;
    }

    tracing::info!(message = "Started DB watcher", path = ?db_path);

    for res in rx {
      match res {
        Ok(event) => {
          // If event paths contain db_path or is a Modify kind, trigger upload
          let should_trigger = event.paths.iter().any(|p| p == &db_path) || matches!(event.kind, notify::EventKind::Modify(_));
          if should_trigger {
            let db_clone = db_arc.clone();
            let upload = upload_url.clone();
            let path_clone = db_path.clone();
            handle.spawn(async move {
              // delay a bit to let file write finish
              tokio::time::sleep(std::time::Duration::from_secs(2)).await;
              match tokio::fs::read(&path_clone).await {
                Ok(bytes) => {
                  let client = &*consts::REQWEST;
                  // Try to read token from DB to set Authorization
                  let token_kv = KvMut::from(db_clone.as_ref(), consts::KV_PAN_OAUTH);
                  let token_read = token_kv.try_read_val_json::<TokenResponse>().await.ok().and_then(|r| r.transpose().ok());

                  let mut req = client.post(&upload).body(bytes.clone());
                  if let Some(token) = token_read {
                    let bearer = format!("Bearer {}", token.access_token);
                    req = req.header("Authorization", bearer);
                  }
                  req = req.header("Content-Type", "application/octet-stream");

                  match req.send().await {
                    Ok(r) => {
                      if !r.status().is_success() {
                        tracing::error!(message = "DB upload failed", status = ?r.status());
                      } else {
                        tracing::info!(message = "DB uploaded successfully", status = ?r.status());
                      }
                    }
                    Err(e) => tracing::error!(message = "DB upload error", ?e),
                  }
                }
                Err(e) => tracing::error!(message = "Read DB file error", ?e),
              }
            });
          }
        }
        Err(e) => tracing::error!(message = "Watch event error", ?e),
      }
    }
  });

  Ok(())
}
