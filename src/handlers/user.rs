use actix_identity::Identity;
use actix_web::{HttpResponse, Responder, delete, get, post, put, web};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::error::AppError;
use crate::error::AppResult;
use crate::state::AppState;
use crate::utils::is_valid_username;

#[derive(Deserialize)]
struct CreateUserPayload {
    username: String,
}

#[derive(Deserialize)]
struct LinksPayload {
    links: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct OrderPayload {
    order: Vec<String>,
}

#[get("/api/users")]
pub async fn list_users(_id: Identity, data: web::Data<AppState>) -> AppResult<impl Responder> {
    let rows = sqlx::query("SELECT username FROM users ORDER BY rank ASC")
        .fetch_all(&data.db)
        .await?;

    let list: Vec<String> = rows.iter().map(|r| r.get("username")).collect();
    Ok(HttpResponse::Ok().json(list))
}

#[post("/api/users")]
pub async fn create_user(
    _id: Identity,
    payload: web::Json<CreateUserPayload>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    let username = payload.username.trim().to_string();

    if !is_valid_username(&username) {
        return Err(AppError::BadRequest("Invalid username".into()));
    }

    let max_rank_res = sqlx::query("SELECT MAX(rank) FROM users")
        .fetch_one(&data.db)
        .await;

    let next_rank: i64 = match max_rank_res {
        Ok(row) => row.try_get::<i64, _>(0).unwrap_or(0) + 1,
        Err(_) => 1,
    };

    let result = sqlx::query("INSERT INTO users (username, links, rank) VALUES ($1, '[]', $2)")
        .bind(&username)
        .bind(next_rank)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            tracing::info!(%username, "user created");
            Ok(HttpResponse::Created().json(username))
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("duplicate key value") || msg.contains("unique constraint") {
                Err(AppError::BadRequest("user exists".into()))
            } else {
                Err(AppError::DbError(e))
            }
        }
    }
}

#[delete("/api/users/{username}")]
pub async fn delete_user(
    _id: Identity,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    let username = path.into_inner();

    let res = sqlx::query("DELETE FROM users WHERE username = $1")
        .bind(&username)
        .execute(&data.db)
        .await?;

    if res.rows_affected() > 0 {
        tracing::info!(%username, "user deleted");
        Ok(HttpResponse::Ok().body("deleted"))
    } else {
        Err(AppError::NotFound("not found".into()))
    }
}

#[get("/api/users/{username}/links")]
pub async fn get_links(
    _id: Identity,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    let username = path.into_inner();

    let row = sqlx::query("SELECT links FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&data.db)
        .await?;

    match row {
        Some(r) => {
            let links: serde_json::Value = r.get("links");
            Ok(HttpResponse::Ok().json(links))
        }
        None => Err(AppError::NotFound("user not found".into())),
    }
}

#[put("/api/users/{username}/links")]
pub async fn set_links(
    _id: Identity,
    path: web::Path<String>,
    payload: web::Json<LinksPayload>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    for link in &payload.links {
        if !link.starts_with("http://") && !link.starts_with("https://") {
            return Err(AppError::BadRequest(format!("Invalid URL: {}", link)));
        }
    }

    let username = path.into_inner();
    let links_value = serde_json::to_value(&payload.links).unwrap_or(serde_json::json!([]));

    let res = sqlx::query("UPDATE users SET links = $1 WHERE username = $2")
        .bind(&links_value)
        .bind(&username)
        .execute(&data.db)
        .await?;

    if res.rows_affected() > 0 {
        Ok(HttpResponse::Ok().json(&payload.links))
    } else {
        Err(AppError::NotFound("user not found".into()))
    }
}

#[put("/api/users/order")]
pub async fn set_user_order(
    _id: Identity,
    payload: web::Json<OrderPayload>,
    data: web::Data<AppState>,
) -> AppResult<impl Responder> {
    let order = &payload.order;
    if order.is_empty() {
        return Err(AppError::BadRequest("order must not be empty".into()));
    }

    let mut tx = data.db.begin().await?;

    for (i, username) in order.iter().enumerate() {
        sqlx::query("UPDATE users SET rank = $1 WHERE username = $2")
            .bind(i as i64)
            .bind(username)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    tracing::info!("User order updated");
    Ok(HttpResponse::Ok().json(order))
}
