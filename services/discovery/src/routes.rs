use axum::{Router, routing::get};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::registry::AppState;

pub fn build_web_router(state: AppState) -> Router {
    Router::new()
        .route("/api/dashboard", get(handlers::dashboard_handler))
        .with_state(state)
        .fallback(handlers::serve_asset)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
