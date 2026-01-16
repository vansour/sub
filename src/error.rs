use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use derive_more::derive::Display;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Display)]
pub enum AppError {
    #[display("Database error: {_0}")]
    DbError(sqlx::Error),

    #[display("Internal server error: {_0}")]
    InternalError(String),

    #[display("Invalid input: {_0}")]
    BadRequest(String),

    #[display("Unauthorized")]
    Unauthorized,

    #[display("Not found")]
    NotFound(String),
    // #[display("Fetch error: {_0}")]
    // FetchError(String),
}

impl std::error::Error for AppError {}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DbError(err)
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::DbError(_) | AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
