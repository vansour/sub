use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::str::FromStr;

/// 数据库连接池
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

/// 用户数据库模型
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub username: String,
    pub urls: Vec<String>,
    pub order_index: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Database {
    /// 初始化数据库连接
    pub async fn new(database_path: &str) -> anyhow::Result<Self> {
        // 确保数据库目录存在
        if let Some(parent) = std::path::Path::new(database_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // 配置连接选项
        let options = SqliteConnectOptions::from_str(database_path)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal) // 使用 WAL 模式提升性能
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        // 创建连接池
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let db = Database { pool };

        // 初始化数据库表
        db.init_schema().await?;

        Ok(db)
    }

    /// 初始化数据库表结构
    async fn init_schema(&self) -> anyhow::Result<()> {
        // 创建用户表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                urls TEXT NOT NULL,
                order_index INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // 创建配置表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // 创建索引
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_users_order ON users(order_index)
            "#,
        )
        .execute(&self.pool)
        .await?;

        tracing::info!("Database schema initialized");
        Ok(())
    }

    /// 获取用户
    pub async fn get_user(&self, username: &str) -> anyhow::Result<Option<UserRecord>> {
        let row = sqlx::query(
            r#"
            SELECT username, urls, order_index, created_at, updated_at
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let urls_json: String = row.try_get("urls")?;
            let urls: Vec<String> = serde_json::from_str(&urls_json)?;

            Ok(Some(UserRecord {
                username: row.try_get("username")?,
                urls,
                order_index: row.try_get("order_index")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            }))
        } else {
            Ok(None)
        }
    }

    /// 获取所有用户（按 order_index 排序）
    pub async fn get_all_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT username, urls, order_index, created_at, updated_at
            FROM users
            ORDER BY order_index ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut users = Vec::new();
        for row in rows {
            let urls_json: String = row.try_get("urls")?;
            let urls: Vec<String> = serde_json::from_str(&urls_json)?;

            users.push(UserRecord {
                username: row.try_get("username")?,
                urls,
                order_index: row.try_get("order_index")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            });
        }

        Ok(users)
    }

    /// 创建或更新用户
    pub async fn upsert_user(
        &self,
        username: &str,
        urls: &[String],
        order_index: i64,
    ) -> anyhow::Result<()> {
        let urls_json = serde_json::to_string(urls)?;
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            r#"
            INSERT INTO users (username, urls, order_index, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                urls = excluded.urls,
                order_index = excluded.order_index,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(username)
        .bind(&urls_json)
        .bind(order_index)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 删除用户
    pub async fn delete_user(&self, username: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM users WHERE username = ?
            "#,
        )
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 批量更新用户顺序
    pub async fn update_user_orders(
        &self,
        order_map: &std::collections::HashMap<String, i64>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;

        for (username, new_order) in order_map.iter() {
            sqlx::query("UPDATE users SET order_index = ?1, updated_at = CURRENT_TIMESTAMP WHERE username = ?2")
                .bind(new_order)
                .bind(username)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// 获取用户数量
    pub async fn count_users(&self) -> anyhow::Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count FROM users
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.try_get("count")?)
    }

    /// 检查用户是否存在
    pub async fn user_exists(&self, username: &str) -> anyhow::Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count FROM users WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = row.try_get("count")?;
        Ok(count > 0)
    }

    /// 健康检查
    pub async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }

    /// 获取配置值
    pub async fn get_config(&self, key: &str) -> anyhow::Result<Option<String>> {
        let result = sqlx::query("SELECT value FROM config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;

        Ok(result.map(|row| row.get("value")))
    }

    /// 设置配置值
    pub async fn set_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            r#"
            INSERT INTO config (key, value, updated_at) 
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET 
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_operations() {
        // 使用内存数据库进行测试
        let db = Database::new("sqlite::memory:").await.unwrap();

        // 测试创建用户
        db.upsert_user("testuser", &vec!["https://example.com".to_string()], 1)
            .await
            .unwrap();

        // 测试获取用户
        let user = db.get_user("testuser").await.unwrap();
        assert!(user.is_some());
        let user = user.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.urls.len(), 1);

        // 测试用户数量
        let count = db.count_users().await.unwrap();
        assert_eq!(count, 1);

        // 测试删除用户
        let deleted = db.delete_user("testuser").await.unwrap();
        assert!(deleted);

        let count = db.count_users().await.unwrap();
        assert_eq!(count, 0);
    }
}
