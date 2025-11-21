use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, services::{ServeDir, ServeFile}, trace::TraceLayer};
use uuid::Uuid;

static KEK_ENV: &str = "SONGMI_KEK_B64";
static DEFAULT_TTL_SECONDS: u64 = 3600;
static MAX_TTL_SECONDS: u64 = 86_400; // 24h safeguard

#[derive(Clone)]
struct AppState {
    storage: Arc<Mutex<HashMap<String, SecretRecord>>>,
    kek: Arc<[u8; 32]>,
    public_base: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct VerifyHint {
    length: usize,
    prefix: String,
    suffix: String,
    classes: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct SecretRecord {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    hint: VerifyHint,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    retrieved_at: Option<DateTime<Utc>>,
    retrieved_ip: Option<String>,
    retrieved_ua: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NewSecretRequest {
    password: Option<String>,
    ttl: Option<u64>,
}

#[derive(Serialize)]
struct NewSecretResponse {
    url: String,
    password: String,
    verify_hint: VerifyHint,
}

#[derive(Serialize)]
struct SecretStatusResponse {
    exists: bool,
    retrieved: bool,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ConsumeResponse {
    FirstRead {
        password: String,
        retrieved: bool,
    },
    AlreadyRead {
        retrieved: bool,
        first_visitor: Option<VisitorInfo>,
    },
}

#[derive(Serialize, Deserialize, Clone)]
struct VisitorInfo {
    ip: Option<String>,
    ua: Option<String>,
    at: Option<DateTime<Utc>>,
}

#[derive(Error, Debug)]
enum AppError {
    #[error("secret not found")]
    NotFound,
    #[error("secret expired")]
    Expired,
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Expired | AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = serde_json::json!({"error": self.to_string()});
        (status, Json(body)).into_response()
    }
}

#[tokio::main]
async fn main() {
    let kek = load_kek();
    let state = AppState {
        storage: Arc::new(Mutex::new(HashMap::new())),
        kek: Arc::new(kek),
        public_base: std::env::var("PUBLIC_BASE").unwrap_or_else(|_| "http://127.0.0.1:3001".to_string()),
    };

    tokio::spawn(cleanup_task(state.clone()));

    let static_dir = ServeDir::new("static").not_found_service(fallback_index());

    let app = Router::new()
        .route("/api/new", post(create_secret))
        .route("/api/s/:token/meta", get(get_status))
        .route("/api/s/:token/consume", post(consume_secret))
        .nest_service("/", static_dir)
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::very_permissive()),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("bind 3001");
    println!("🚀 SongMi service running on http://127.0.0.1:3001");
    let make = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, make).await.unwrap();
}

fn fallback_index() -> ServeFile {
    ServeFile::new("static/index.html")
}

async fn create_secret(
    State(state): State<AppState>,
    Json(payload): Json<NewSecretRequest>,
) -> Result<Json<NewSecretResponse>, AppError> {
    let ttl = payload.ttl.unwrap_or(DEFAULT_TTL_SECONDS).min(MAX_TTL_SECONDS);
    let password = payload
        .password
        .unwrap_or_else(|| generate_password(20));
    let (ciphertext, nonce) = encrypt(&state.kek, password.as_bytes()).map_err(|_| AppError::Internal)?;

    let hint = build_hint(&password);
    let now = Utc::now();
    let expires_at = now + ChronoDuration::seconds(ttl as i64);
    let token = Uuid::new_v4().simple().to_string();

    let record = SecretRecord {
        ciphertext,
        nonce,
        hint: hint.clone(),
        created_at: now,
        expires_at,
        retrieved_at: None,
        retrieved_ip: None,
        retrieved_ua: None,
    };

    state.storage.lock().await.insert(token.clone(), record);

    let url = format!("{}/s/{}", state.public_base.trim_end_matches('/'), token);
    Ok(Json(NewSecretResponse { url, password, verify_hint: hint }))
}

async fn get_status(
    Path(token): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<SecretStatusResponse>, AppError> {
    let map = state.storage.lock().await;
    let Some(rec) = map.get(&token) else {
        return Err(AppError::NotFound);
    };
    if rec.expires_at < Utc::now() {
        return Err(AppError::Expired);
    }

    Ok(Json(SecretStatusResponse {
        exists: true,
        retrieved: rec.retrieved_at.is_some(),
        expires_at: Some(rec.expires_at),
    }))
}

async fn consume_secret(
    Path(token): Path<String>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ConsumeResponse>, AppError> {
    let mut map = state.storage.lock().await;
    let Some(rec) = map.get_mut(&token) else {
        return Err(AppError::NotFound);
    };

    if rec.expires_at < Utc::now() {
        return Err(AppError::Expired);
    }

    // Already read
    if rec.retrieved_at.is_some() {
        let visitor = VisitorInfo {
            ip: rec.retrieved_ip.clone(),
            ua: rec.retrieved_ua.clone(),
            at: rec.retrieved_at,
        };
        return Ok(Json(ConsumeResponse::AlreadyRead {
            retrieved: true,
            first_visitor: Some(visitor),
        }));
    }

    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ip = mask_ip(addr.ip());
    rec.retrieved_at = Some(Utc::now());
    rec.retrieved_ip = Some(ip.clone());
    rec.retrieved_ua = Some(ua.clone());

    let plaintext = decrypt(&state.kek, &rec.ciphertext, &rec.nonce).map_err(|_| AppError::Internal)?;
    let password = String::from_utf8_lossy(&plaintext).to_string();
    Ok(Json(ConsumeResponse::FirstRead {
        password,
        retrieved: false,
    }))
}

fn generate_password(len: usize) -> String {
    let symbols = b"!@#$%^&*()-_=+[]{}";
    let mut rng = OsRng;
    (0..len)
        .map(|_| {
            let pick: u8 = rng.gen_range(0..4);
            match pick {
                0 => rng.sample(Alphanumeric) as char,
                1 => (rng.gen_range(b'a'..=b'z')) as char,
                2 => (rng.gen_range(b'A'..=b'Z')) as char,
                _ => symbols[rng.gen_range(0..symbols.len())] as char,
            }
        })
        .collect()
}

fn build_hint(password: &str) -> VerifyHint {
    let length = password.chars().count();
    let prefix: String = password.chars().take(2).collect();
    let suffix: String = password.chars().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
    let mut classes = 0;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 1;
    }

    VerifyHint {
        length,
        prefix,
        suffix,
        classes,
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), AppError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AppError::Internal)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AppError::Internal)?;
    Ok((ciphertext, nonce_bytes))
}

fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AppError::Internal)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::Internal)
}

fn mask_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.xxx.xxx", octets[0], octets[1])
        }
        std::net::IpAddr::V6(_) => "ipv6".to_string(),
    }
}

fn load_kek() -> [u8; 32] {
    if let Ok(val) = std::env::var(KEK_ENV) {
        if let Ok(bytes) = general_purpose::STANDARD.decode(val) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return arr;
            }
        }
        println!("⚠️  Invalid {KEK_ENV}, generating ephemeral key.");
    }
    println!("ℹ️  Generated ephemeral KEK (set {KEK_ENV} for persistence).");
    let mut arr = [0u8; 32];
    OsRng.fill_bytes(&mut arr);
    arr
}

async fn cleanup_task(state: AppState) {
    loop {
        sleep(Duration::from_secs(60)).await;
        let now = Utc::now();
        let mut map = state.storage.lock().await;
        map.retain(|_, rec| {
            if rec.expires_at < now {
                return false;
            }
            true
        });
    }
}
