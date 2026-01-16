use actix_identity::Identity;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, put, web};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use serde::Deserialize;
use sqlx::Row;

use crate::error::AppError;
use crate::error::AppResult;
use crate::state::AppState;
use crate::utils::is_valid_username;

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UpdateAccountPayload {
    new_username: String,
    new_password: String,
}

#[post("/api/auth/login")]
pub async fn login(
    req: HttpRequest,
    payload: web::Json<LoginPayload>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    let row = sqlx::query("SELECT password_hash FROM admins WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(&data.db)
        .await?;

    if let Some(r) = row {
        let hash_str: String = r.get(0);
        let parsed_hash = PasswordHash::new(&hash_str).map_err(|e| {
            tracing::error!("Invalid password hash stored in DB: {}", e);
            AppError::InternalError("Auth error".into())
        })?;

        if Argon2::default()
            .verify_password(payload.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            Identity::login(&req.extensions(), payload.username.clone()).map_err(|e| {
                tracing::error!("Failed to attach identity: {}", e);
                AppError::InternalError("Login session error".into())
            })?;
            return Ok(HttpResponse::Ok().json("Logged in"));
        }
    }

    Err(AppError::Unauthorized)
}

#[post("/api/auth/logout")]
pub async fn logout(id: Identity) -> impl Responder {
    id.logout();
    HttpResponse::Ok().body("Logged out")
}

#[get("/api/auth/me")]
pub async fn get_me(id: Option<Identity>) -> AppResult<impl Responder> {
    match id {
        Some(id) => {
            let username = id.id().map_err(|e| {
                tracing::warn!("Identity found but ID is invalid: {}", e);
                AppError::Unauthorized
            })?;
            Ok(HttpResponse::Ok().json(serde_json::json!({ "username": username })))
        }
        None => Err(AppError::Unauthorized),
    }
}

#[put("/api/auth/account")]
pub async fn update_account(
    id: Identity,
    payload: web::Json<UpdateAccountPayload>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    let current_user = id.id().map_err(|_| AppError::Unauthorized)?;

    let new_username = payload.new_username.trim();
    let new_password = payload.new_password.trim();

    if !is_valid_username(new_username) {
        return Err(AppError::BadRequest("Invalid username format".into()));
    }
    if new_password.is_empty() {
        return Err(AppError::BadRequest("Password cannot be empty".into()));
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalError(format!("Hash error: {}", e)))?
        .to_string();

    sqlx::query("UPDATE admins SET username = $1, password_hash = $2 WHERE username = $3")
        .bind(new_username)
        .bind(password_hash)
        .bind(&current_user)
        .execute(&data.db)
        .await
        .map_err(|e| {
            tracing::error!("Update account error: {}", e);
            AppError::InternalError("Failed to update account (username might exist)".into())
        })?;

    id.logout();
    Ok(HttpResponse::Ok().body("Account updated, please login again"))
}
