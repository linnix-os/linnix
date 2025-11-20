use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn auth_middleware(
    State(expected_token): State<Option<String>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = expected_token else {
        return next.run(request).await;
    };

    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
        && token == expected
    {
        return next.run(request).await;
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}
