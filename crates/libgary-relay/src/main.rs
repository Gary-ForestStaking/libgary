//! Opaque binary relay over WebSocket: pairs one host + one guest per `(room, pin_tag)` bucket.
//! TLS is expected at the edge (nginx); clients speak `wss://`.

use axum::{
    Json,
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct Hub {
    rooms: Arc<Mutex<HashMap<String, RoomEntry>>>,
}

enum RoomEntry {
    HostWaiting {
        ws: WebSocket,
        notify: Arc<Notify>,
    },
    GuestWaiting {
        ws: WebSocket,
        notify: Arc<Notify>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Host,
    Guest,
}

#[derive(Deserialize)]
struct JoinBody {
    room: String,
    pin_tag: String,
    role: Role,
}

#[derive(Serialize)]
struct JoinAck {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    waiting: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

fn validate_pin_tag(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.len() != 16 {
        return None;
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Some(s)
}

fn room_key(room: Uuid, pin_tag: &str) -> String {
    format!("{}|{}", room.as_hyphenated(), pin_tag)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let hub = Hub {
        rooms: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/ws", get(ws_upgrade))
        .layer(TraceLayer::new_for_http())
        .with_state(hub);

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!("libgary-relay listening on http://{addr} (WebSocket /ws)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "libgary-relay",
        "version": env!("CARGO_PKG_VERSION"),
        "ws_path": "/ws",
        "join_schema": {
            "first_message_text_json": {
                "room": "uuid string",
                "pin_tag": "16 hex chars (same as Bonjour PIN discovery tag)",
                "role": "host | guest"
            }
        }
    }))
}

async fn health() -> &'static str {
    "ok"
}

async fn ws_upgrade(
    State(hub): State<Hub>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.max_frame_size(1024 * 1024)
        .max_message_size(1024 * 1024)
        .on_upgrade(move |socket| handle_socket(socket, hub))
}

async fn handle_socket(mut socket: WebSocket, hub: Hub) {
    let join_msg = match socket.next().await {
        Some(Ok(Message::Text(t))) => t,
        Some(Ok(Message::Binary(_))) => {
            let _ = send_join_err(&mut socket, "expected_text_join_first").await;
            return;
        }
        Some(Ok(Message::Close(_))) | None => return,
        Some(Err(e)) => {
            warn!("ws recv join: {e}");
            return;
        }
        Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
            let _ = send_join_err(&mut socket, "expected_text_join_first").await;
            return;
        }
    };

    let join: JoinBody = match serde_json::from_str(&join_msg) {
        Ok(j) => j,
        Err(_) => {
            let _ = send_join_err(&mut socket, "invalid_join_json").await;
            return;
        }
    };

    let room = match Uuid::parse_str(join.room.trim()) {
        Ok(u) => u,
        Err(_) => {
            let _ = send_join_err(&mut socket, "invalid_room_uuid").await;
            return;
        }
    };

    let pin_tag = match validate_pin_tag(&join.pin_tag) {
        Some(p) => p,
        None => {
            let _ = send_join_err(&mut socket, "invalid_pin_tag").await;
            return;
        }
    };

    let key = room_key(room, &pin_tag);

    match join.role {
        Role::Host => handle_role(socket, &hub, key, true).await,
        Role::Guest => handle_role(socket, &hub, key, false).await,
    }
}

async fn send_join_err(socket: &mut WebSocket, code: &'static str) -> Result<(), axum::Error> {
    let body = serde_json::to_string(&JoinAck {
        ok: false,
        waiting: None,
        error: Some(code),
    })
    .unwrap_or_else(|_| r#"{"ok":false}"#.to_string());
    socket.send(Message::Text(body.into())).await?;
    socket.send(Message::Close(None)).await
}

async fn handle_role(mut socket: WebSocket, hub: &Hub, key: String, is_host: bool) {
    let notify_wait = {
        let mut map = hub.rooms.lock().await;
        if is_host {
            if matches!(map.get(&key), Some(RoomEntry::HostWaiting { .. })) {
                drop(map);
                let _ = send_join_err(&mut socket, "duplicate_host").await;
                return;
            }
            match map.remove(&key) {
                Some(RoomEntry::GuestWaiting { ws: peer, notify }) => {
                    drop(map);
                    notify.notify_waiters();
                    let ack = serde_json::to_string(&JoinAck {
                        ok: true,
                        waiting: Some(false),
                        error: None,
                    })
                    .unwrap();
                    let _ = socket.send(Message::Text(ack.into())).await;
                    info!(room_key = %key, "paired host with waiting guest");
                    relay_pair(socket, peer).await;
                    return;
                }
                Some(RoomEntry::HostWaiting { .. }) => unreachable!("checked above"),
                None => {}
            }
            let notify = Arc::new(Notify::new());
            let n = notify.clone();
            map.insert(
                key.clone(),
                RoomEntry::HostWaiting {
                    ws: socket,
                    notify,
                },
            );
            n
        } else {
            if matches!(map.get(&key), Some(RoomEntry::GuestWaiting { .. })) {
                drop(map);
                let _ = send_join_err(&mut socket, "duplicate_guest").await;
                return;
            }
            match map.remove(&key) {
                Some(RoomEntry::HostWaiting { ws: peer, notify }) => {
                    drop(map);
                    notify.notify_waiters();
                    let ack = serde_json::to_string(&JoinAck {
                        ok: true,
                        waiting: Some(false),
                        error: None,
                    })
                    .unwrap();
                    let _ = socket.send(Message::Text(ack.into())).await;
                    info!(room_key = %key, "paired guest with waiting host");
                    relay_pair(peer, socket).await;
                    return;
                }
                Some(RoomEntry::GuestWaiting { .. }) => unreachable!("checked above"),
                None => {}
            }
            let notify = Arc::new(Notify::new());
            let n = notify.clone();
            map.insert(
                key.clone(),
                RoomEntry::GuestWaiting {
                    ws: socket,
                    notify,
                },
            );
            n
        }
    };

    // Waiting for peer (socket stored in map).
    let ack = serde_json::to_string(&JoinAck {
        ok: true,
        waiting: Some(true),
        error: None,
    })
    .unwrap();
    {
        let mut guard = hub.rooms.lock().await;
        let Some(entry) = guard.get_mut(&key) else {
            return;
        };
        let ws_mut = match entry {
            RoomEntry::HostWaiting { ws, .. } | RoomEntry::GuestWaiting { ws, .. } => ws,
        };
        if ws_mut
            .send(Message::Text(ack.into()))
            .await
            .is_err()
        {
            guard.remove(&key);
            return;
        }
    }

    notify_wait.notified().await;
    info!(room_key = %key, "wait ended (paired elsewhere)");
}

async fn relay_pair(mut a: WebSocket, mut b: WebSocket) {
    loop {
        tokio::select! {
            msg = a.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if b.send(Message::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(v))) => {
                        let _ = a.send(Message::Pong(v)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        let _ = b.send(Message::Close(frame)).await;
                        break;
                    }
                    Some(Ok(Message::Text(_))) => break,
                    Some(Err(_)) | None => break,
                }
            }
            msg = b.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if a.send(Message::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(v))) => {
                        let _ = b.send(Message::Pong(v)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        let _ = a.send(Message::Close(frame)).await;
                        break;
                    }
                    Some(Ok(Message::Text(_))) => break,
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
    let _ = a.close().await;
    let _ = b.close().await;
}
