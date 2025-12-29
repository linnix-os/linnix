use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
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

    if let Some(auth_header) = headers.get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
        && token == expected
    {
        return next.run(request).await;
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, middleware, routing::get};
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "OK"
    }

    #[tokio::test]
    async fn test_auth_middleware_with_no_token_configured() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn_with_state(
                None::<String>,
                auth_middleware,
            ))
            .with_state(None::<String>);

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_with_correct_token() {
        let expected_token = "test-token-123".to_string();
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn_with_state(
                Some(expected_token.clone()),
                auth_middleware,
            ))
            .with_state(Some(expected_token.clone()));

        let request = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer test-token-123")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_with_incorrect_token() {
        let expected_token = "test-token-123".to_string();
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn_with_state(
                Some(expected_token.clone()),
                auth_middleware,
            ))
            .with_state(Some(expected_token));

        let request = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_without_header() {
        let expected_token = "test-token-123".to_string();
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn_with_state(
                Some(expected_token.clone()),
                auth_middleware,
            ))
            .with_state(Some(expected_token));

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_without_bearer_prefix() {
        let expected_token = "test-token-123".to_string();
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn_with_state(
                Some(expected_token.clone()),
                auth_middleware,
            ))
            .with_state(Some(expected_token));

        let request = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "test-token-123")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
