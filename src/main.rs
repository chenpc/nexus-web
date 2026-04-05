use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use libnexus::proto::{
    nexus_service_client::NexusServiceClient, CommandRequest, CommandResponse,
    ListServicesRequest, ListServicesResponse,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

type Client = Arc<Mutex<NexusServiceClient<Channel>>>;
type SessionStore = Arc<Mutex<HashMap<String, String>>>;

#[derive(Clone)]
struct AppState {
    client: Client,
    sessions: SessionStore,
}

#[derive(Deserialize)]
struct ExecuteRequest {
    service: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Serialize)]
struct ExecuteResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
struct ArgDef {
    name: String,
    hint: String,
    description: String,
}

#[derive(Serialize)]
struct CommandDef {
    name: String,
    description: String,
    args: Vec<ArgDef>,
}

#[derive(Serialize)]
struct ServiceInfo {
    name: String,
    description: String,
    commands: Vec<CommandDef>,
}

#[derive(Serialize)]
struct UserInfo {
    username: String,
    uid: u32,
    comment: String,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    comment: String,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct CreatePoolRequest {
    name: String,
    raid_type: String,
    devices: Vec<String>,
}

#[derive(Deserialize)]
struct CreateVolumeRequest {
    name: String,
    pool: String,
}

#[derive(Deserialize)]
struct SetPermissionRequest {
    dataset: String,
    user: String,
    access: String,
}

#[derive(Deserialize)]
struct RevokePermissionRequest {
    dataset: String,
    user: String,
}

#[derive(Deserialize)]
struct PermissionQuery {
    dataset: String,
}

async fn list_services(State(state): State<AppState>) -> impl IntoResponse {
    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<ListServicesResponse>, tonic::Status> =
        guard.list_services(tonic::Request::new(ListServicesRequest {})).await;
    match result {
        Ok(resp) => {
            let body: ListServicesResponse = resp.into_inner();
            let services: Vec<ServiceInfo> = body
                .services
                .into_iter()
                .map(|s| ServiceInfo {
                    name: s.name,
                    description: s.description,
                    commands: s
                        .commands
                        .into_iter()
                        .map(|c| CommandDef {
                            name: c.name,
                            description: c.description,
                            args: c
                                .args
                                .into_iter()
                                .map(|a| ArgDef {
                                    name: a.name,
                                    hint: a.hint,
                                    description: a.description,
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect();
            Json(serde_json::json!({"services": services})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

async fn execute(
    State(state): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: req.service,
        action: req.command,
        args: req.args,
    };
    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;
    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            Json(ExecuteResponse {
                success: r.success,
                message: r.message,
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExecuteResponse {
                success: false,
                message: format!("{}", e),
            }),
        )
            .into_response(),
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn login_page() -> Html<&'static str> {
    Html(include_str!("login.html"))
}

// Authentication middleware
async fn auth_middleware(
    jar: CookieJar,
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Redirect> {
    if let Some(cookie) = jar.get("nexus_session") {
        let sessions = state.sessions.lock().await;
        if sessions.contains_key(cookie.value()) {
            return Ok(next.run(request).await);
        }
    }
    Err(Redirect::to("/login"))
}

// Password verification
fn verify_password(username: &str, password: &str) -> bool {
    // Read /etc/shadow to find the user's password hash
    let shadow_content = match std::fs::read_to_string("/etc/shadow") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read /etc/shadow: {}", e);
            return false;
        }
    };

    for line in shadow_content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        if parts[0] != username {
            continue;
        }
        let hash = parts[1];
        // Empty password or disabled account
        if hash.is_empty() || hash == "!" || hash == "*" || hash == "!!" {
            return false;
        }
        // Verify using pwhash crate (supports $6$ SHA-512, $5$ SHA-256, $1$ MD5)
        return pwhash::unix::verify(password, hash);
    }
    false
}

// Generate random session token
fn generate_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

// Login handler
async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    if verify_password(&req.username, &req.password) {
        let token = generate_token();
        let mut sessions = state.sessions.lock().await;
        sessions.insert(token.clone(), req.username);

        let cookie = Cookie::build(("nexus_session", token))
            .path("/")
            .http_only(true)
            .build();

        Ok((jar.add(cookie), Redirect::to("/")))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// Logout handler
async fn logout(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, Redirect) {
    if let Some(cookie) = jar.get("nexus_session") {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(cookie.value());
    }

    let cookie = Cookie::build(("nexus_session", ""))
        .path("/")
        .build();

    (jar.remove(cookie), Redirect::to("/login"))
}

// List users
async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "user".to_string(),
        action: "list".to_string(),
        args: vec![],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                // Parse the JSON response from message field
                match serde_json::from_str::<serde_json::Value>(&r.message) {
                    Ok(data) => {
                        // Convert NamedMap to Vec<UserInfo>
                        let users: Vec<UserInfo> = if let Some(obj) = data.as_object() {
                            obj.iter()
                                .filter_map(|(username, info)| {
                                    let uid = info["uid"].as_u64()? as u32;
                                    let comment = info["comment"].as_str().unwrap_or("").to_string();
                                    Some(UserInfo {
                                        username: username.clone(),
                                        uid,
                                        comment,
                                    })
                                })
                                .collect()
                        } else {
                            vec![]
                        };
                        Json(serde_json::json!({"users": users})).into_response()
                    }
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("Failed to parse response: {}", e)})),
                    )
                        .into_response(),
                }
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Create user
async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "user".to_string(),
        action: "create".to_string(),
        args: vec![req.username, req.password, req.comment],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({"success": true})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Delete user
async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "user".to_string(),
        action: "delete".to_string(),
        args: vec![username],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                Json(serde_json::json!({"success": true})).into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Change password
async fn change_password(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "user".to_string(),
        action: "passwd".to_string(),
        args: vec![username, req.password],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                Json(serde_json::json!({"success": true})).into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// List pools
async fn list_pools(State(state): State<AppState>) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "pool".to_string(),
        action: "list".to_string(),
        args: vec![],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                // Parse the JSON response
                match serde_json::from_str::<serde_json::Value>(&r.message) {
                    Ok(data) => Json(data).into_response(),
                    Err(_) => {
                        // If not JSON, return as plain text wrapped in object
                        Json(serde_json::json!({"data": r.message})).into_response()
                    }
                }
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Create pool
async fn create_pool(
    State(state): State<AppState>,
    Json(req): Json<CreatePoolRequest>,
) -> impl IntoResponse {
    let mut args = vec![req.name, req.raid_type];
    args.extend(req.devices);

    let grpc_req = CommandRequest {
        service: "pool".to_string(),
        action: "create".to_string(),
        args,
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({"success": true, "message": r.message})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Delete pool
async fn delete_pool(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "pool".to_string(),
        action: "destroy".to_string(),
        args: vec![name],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                Json(serde_json::json!({"success": true, "message": r.message})).into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// List blocks
async fn list_blocks(State(state): State<AppState>) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "block".to_string(),
        action: "list".to_string(),
        args: vec![],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                // Parse the JSON response
                match serde_json::from_str::<serde_json::Value>(&r.message) {
                    Ok(data) => Json(data).into_response(),
                    Err(_) => {
                        // If not JSON, return as plain text wrapped in object
                        Json(serde_json::json!({"data": r.message})).into_response()
                    }
                }
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// List volumes
async fn list_volumes(State(state): State<AppState>) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "volume".to_string(),
        action: "list".to_string(),
        args: vec![],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                // Parse the JSON response
                match serde_json::from_str::<serde_json::Value>(&r.message) {
                    Ok(data) => Json(data).into_response(),
                    Err(_) => {
                        // If not JSON, return as plain text wrapped in object
                        Json(serde_json::json!({"data": r.message})).into_response()
                    }
                }
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Create volume
async fn create_volume(
    State(state): State<AppState>,
    Json(req): Json<CreateVolumeRequest>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "volume".to_string(),
        action: "create".to_string(),
        args: vec![req.name, req.pool],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({"success": true, "message": r.message})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// Delete volume
async fn delete_volume(
    State(state): State<AppState>,
    Path(dataset): Path<String>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "volume".to_string(),
        action: "delete".to_string(),
        args: vec![dataset],
    };

    let mut guard = state.client.lock().await;
    let result: Result<tonic::Response<CommandResponse>, tonic::Status> =
        guard.execute(tonic::Request::new(grpc_req)).await;

    match result {
        Ok(resp) => {
            let r: CommandResponse = resp.into_inner();
            if r.success {
                Json(serde_json::json!({"success": true, "message": r.message})).into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": r.message})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

// GET /api/volume-permissions?dataset=pool/vol
async fn list_volume_permissions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<PermissionQuery>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "volume".to_string(),
        action: "permissions".to_string(),
        args: vec![q.dataset],
    };
    let mut guard = state.client.lock().await;
    match guard.execute(tonic::Request::new(grpc_req)).await {
        Ok(resp) => {
            let r = resp.into_inner();
            if r.success {
                match serde_json::from_str::<serde_json::Value>(&r.message) {
                    Ok(data) => Json(data).into_response(),
                    Err(_) => Json(serde_json::json!({})).into_response(),
                }
            } else {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": r.message}))).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}

// POST /api/volume-permissions  {dataset, user, access}
async fn set_volume_permission(
    State(state): State<AppState>,
    Json(req): Json<SetPermissionRequest>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "volume".to_string(),
        action: "permission".to_string(),
        args: vec![req.dataset, req.user, req.access],
    };
    let mut guard = state.client.lock().await;
    match guard.execute(tonic::Request::new(grpc_req)).await {
        Ok(resp) => {
            let r = resp.into_inner();
            if r.success {
                Json(serde_json::json!({"success": true, "message": r.message})).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": r.message}))).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}

// DELETE /api/volume-permissions  {dataset, user}
async fn revoke_volume_permission(
    State(state): State<AppState>,
    Json(req): Json<RevokePermissionRequest>,
) -> impl IntoResponse {
    let grpc_req = CommandRequest {
        service: "volume".to_string(),
        action: "revoke".to_string(),
        args: vec![req.dataset, req.user],
    };
    let mut guard = state.client.lock().await;
    match guard.execute(tonic::Request::new(grpc_req)).await {
        Ok(resp) => {
            let r = resp.into_inner();
            if r.success {
                Json(serde_json::json!({"success": true, "message": r.message})).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": r.message}))).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}

// POST /api/factory-reset — destroy all pools and delete all non-root users
async fn factory_reset(State(state): State<AppState>) -> impl IntoResponse {
    let mut guard = state.client.lock().await;
    let mut messages = Vec::new();

    // 1. Destroy all pools (which also destroys volumes)
    let pool_list = guard
        .execute(tonic::Request::new(CommandRequest {
            service: "pool".to_string(),
            action: "list".to_string(),
            args: vec![],
        }))
        .await;
    if let Ok(resp) = pool_list {
        let r = resp.into_inner();
        if r.success {
            if let Ok(pools) = serde_json::from_str::<serde_json::Value>(&r.message) {
                if let Some(obj) = pools.as_object() {
                    for pool_name in obj.keys() {
                        let _ = guard
                            .execute(tonic::Request::new(CommandRequest {
                                service: "pool".to_string(),
                                action: "destroy".to_string(),
                                args: vec![pool_name.clone()],
                            }))
                            .await;
                        messages.push(format!("Destroyed pool '{}'", pool_name));
                    }
                }
            }
        }
    }

    // 2. Delete all non-root users (uid >= 1000)
    let user_list = guard
        .execute(tonic::Request::new(CommandRequest {
            service: "user".to_string(),
            action: "list".to_string(),
            args: vec![],
        }))
        .await;
    if let Ok(resp) = user_list {
        let r = resp.into_inner();
        if r.success {
            if let Ok(users) = serde_json::from_str::<serde_json::Value>(&r.message) {
                if let Some(obj) = users.as_object() {
                    for (username, info) in obj {
                        let uid = info["uid"].as_u64().unwrap_or(0);
                        if uid >= 1000 {
                            let _ = guard
                                .execute(tonic::Request::new(CommandRequest {
                                    service: "user".to_string(),
                                    action: "delete".to_string(),
                                    args: vec![username.clone()],
                                }))
                                .await;
                            messages.push(format!("Deleted user '{}'", username));
                        }
                    }
                }
            }
        }
    }

    Json(serde_json::json!({"success": true, "messages": messages})).into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let grpc_endpoint = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp/storage-daemon.sock".to_string());

    let channel = if grpc_endpoint.starts_with('/') {
        // Unix domain socket
        let socket_path = grpc_endpoint.clone();
        Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = socket_path.clone();
                async move { UnixStream::connect(path).await.map(TokioIo::new) }
            }))
            .await?
    } else {
        // TCP
        Channel::from_shared(grpc_endpoint.clone())?
            .connect()
            .await?
    };
    let client: Arc<Mutex<NexusServiceClient<Channel>>> =
        Arc::new(Mutex::new(NexusServiceClient::new(channel)));

    let sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    let state = AppState { client, sessions };

    // Protected routes (require authentication)
    let protected = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/api/services", get(list_services))
        .route("/api/execute", post(execute))
        .route("/api/users", get(list_users))
        .route("/api/users", post(create_user))
        .route("/api/users/:username", delete(delete_user))
        .route("/api/users/:username/passwd", post(change_password))
        .route("/api/pools", get(list_pools))
        .route("/api/pools", post(create_pool))
        .route("/api/pools/:name", delete(delete_pool))
        .route("/api/blocks", get(list_blocks))
        .route("/api/volumes", get(list_volumes))
        .route("/api/volumes", post(create_volume))
        .route("/api/volumes/:dataset", delete(delete_volume))
        .route("/api/factory-reset", post(factory_reset))
        .route("/api/volume-permissions", get(list_volume_permissions))
        .route("/api/volume-permissions", post(set_volume_permission))
        .route("/api/volume-permissions", delete(revoke_volume_permission))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Public routes (no authentication)
    let public = Router::new()
        .route("/login", get(login_page))
        .route("/login", post(login))
        .route("/logout", get(logout));

    let app = Router::new()
        .merge(protected)
        .merge(public)
        .with_state(state);

    println!("Connected to gRPC at {}", grpc_endpoint);

    // Parse host and port from addr
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    let port: u16 = parts[0].parse().unwrap_or(443);
    let host = parts.get(1).unwrap_or(&"0.0.0.0").to_string();

    // TLS cert generated by systemd ExecStartPre if not exists
    let cert_path = "/etc/nexus/cert.pem";
    let key_path = "/etc/nexus/key.pem";

    let tls_config = axum_server::tls_openssl::OpenSSLConfig::from_pem_file(cert_path, key_path)?;

    // HTTP → HTTPS redirect server
    let https_port = port;
    let http_port = if port == 443 { 80 } else { port + 1 };
    let redirect_app = Router::new().fallback(move |req: Request<axum::body::Body>| async move {
        let host_header = req.headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost")
            .to_string();
        let hostname = host_header.split(':').next().unwrap_or(&host_header);
        let uri = req.uri().to_string();
        let redirect_url = if https_port == 443 {
            format!("https://{}{}", hostname, uri)
        } else {
            format!("https://{}:{}{}", hostname, https_port, uri)
        };
        Redirect::permanent(&redirect_url)
    });

    let http_addr: std::net::SocketAddr = format!("{}:{}", host, http_port).parse()?;
    let https_addr: std::net::SocketAddr = format!("{}:{}", host, port).parse()?;

    println!("Nexus Web UI listening on https://{} (HTTP redirect on port {})", https_addr, http_port);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, redirect_app).await.unwrap();
    });

    axum_server::bind_openssl(https_addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
