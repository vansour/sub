use crate::errors::AppResult;
use crate::metrics;
use crate::models::{UserData, UserInfo};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

/// 数据服务：负责数据持久化和加载
/// 注意：此服务已被 SQLite 数据库替代，保留用于向后兼容
#[allow(dead_code)]
pub struct DataService {
    store: Arc<RwLock<HashMap<String, UserData>>>,
    data_file_path: String,
}

#[allow(dead_code)]
impl DataService {
    pub fn new(store: Arc<RwLock<HashMap<String, UserData>>>, data_file_path: String) -> Self {
        Self {
            store,
            data_file_path,
        }
    }

    /// 从 data.toml 加载数据到内存
    pub fn load(&self) -> AppResult<()> {
        let start = Instant::now();
        let path = &self.data_file_path;
        if !std::path::Path::new(path).exists() {
            tracing::info!(file = %path, "data file not found, starting with empty store");
            metrics::record_db_operation("load_data", true, start.elapsed().as_secs_f64());
            return Ok(());
        }

        tracing::debug!(file = %path, "loading data from file");

        let content = match std::fs::read_to_string(path) {
            Ok(c) => {
                tracing::debug!(file = %path, size_bytes = c.len(), "data file read successfully");
                c
            }
            Err(e) => {
                tracing::error!(file = %path, error = %e, "failed to read data file");
                metrics::record_db_operation("load_data", false, start.elapsed().as_secs_f64());
                return Err(e.into());
            }
        };

        let data: toml::Value = match toml::from_str(&content) {
            Ok(d) => {
                tracing::debug!(file = %path, "TOML parsing successful");
                d
            }
            Err(e) => {
                tracing::error!(file = %path, error = %e, "failed to parse TOML");
                metrics::record_db_operation("load_data", false, start.elapsed().as_secs_f64());
                return Err(e.into());
            }
        };

        if let Some(links) = data.get("links").and_then(|v| v.as_array()) {
            let mut map = self.store.write();
            let mut loaded_count = 0;

            for (index, link) in links.iter().enumerate() {
                if let (Some(username), Some(urls)) = (
                    link.get("username").and_then(|v| v.as_str()),
                    link.get("urls").and_then(|v| v.as_array()),
                ) {
                    let url_list: Vec<String> = urls
                        .iter()
                        .filter_map(|u| u.as_str().map(String::from))
                        .collect();
                    if !url_list.is_empty() {
                        let order = link
                            .get("order")
                            .and_then(|v| v.as_integer())
                            .map(|v| v as usize)
                            .unwrap_or(index + 1);

                        map.insert(
                            username.to_string(),
                            UserData {
                                urls: url_list.clone(),
                                order,
                            },
                        );
                        loaded_count += 1;
                        tracing::debug!(
                            username = %username,
                            order = order,
                            url_count = url_list.len(),
                            "user loaded from file"
                        );
                    }
                }
            }
            tracing::info!(
                file = %path,
                loaded_users = loaded_count,
                "data loading completed"
            );
        }

        metrics::record_db_operation("load_data", true, start.elapsed().as_secs_f64());
        Ok(())
    }

    /// 将内存中的短链映射写入 data.toml
    /// 使用临时文件 + 原子 rename 确保数据完整性
    pub fn persist(&self) -> AppResult<()> {
        let start = Instant::now();
        let map = self.store.read();
        let mut items: Vec<(String, UserData)> =
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        items.sort_by_key(|(_, data)| data.order);

        let mut toml = String::new();
        for (username, user_data) in items {
            toml.push_str("[[links]]\n");
            toml.push_str(&format!("order = {}\n", user_data.order));
            toml.push_str(&format!("username = \"{}\"\n", username));
            toml.push_str("urls = [");
            for (i, u) in user_data.urls.iter().enumerate() {
                if i > 0 {
                    toml.push_str(", ");
                }
                toml.push_str(&format!("\"{}\"", u));
            }
            toml.push_str("]\n\n");
        }

        let path = &self.data_file_path;
        if let Some(parent) = std::path::Path::new(path).parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!(
                    parent_dir = %parent.display(),
                    error = %e,
                    "failed to create parent directories"
                );
                metrics::record_db_operation("persist_data", false, start.elapsed().as_secs_f64());
                return Err(e.into());
            }
        }

        let tmp_path = format!("{}.tmp.{}", path, std::process::id());
        tracing::debug!(
            target_file = %path,
            temp_file = %tmp_path,
            content_size = toml.len(),
            "writing data to temporary file"
        );

        match std::fs::File::create(&tmp_path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(toml.as_bytes()) {
                    tracing::error!(
                        temp_file = %tmp_path,
                        error = %e,
                        "failed to write to temporary file"
                    );
                    let _ = std::fs::remove_file(&tmp_path);
                    metrics::record_db_operation(
                        "persist_data",
                        false,
                        start.elapsed().as_secs_f64(),
                    );
                    return Err(e.into());
                }
                if let Err(e) = file.sync_all() {
                    tracing::error!(
                        temp_file = %tmp_path,
                        error = %e,
                        "failed to sync file to disk"
                    );
                    let _ = std::fs::remove_file(&tmp_path);
                    metrics::record_db_operation(
                        "persist_data",
                        false,
                        start.elapsed().as_secs_f64(),
                    );
                    return Err(e.into());
                }
            }
            Err(e) => {
                tracing::error!(
                    temp_file = %tmp_path,
                    error = %e,
                    "failed to create temporary file"
                );
                metrics::record_db_operation("persist_data", false, start.elapsed().as_secs_f64());
                return Err(e.into());
            }
        }

        match std::fs::rename(&tmp_path, path) {
            Ok(()) => {
                tracing::info!(
                    file = %path,
                    user_count = map.len(),
                    "data persisted successfully"
                );
                metrics::record_db_operation("persist_data", true, start.elapsed().as_secs_f64());
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    temp_file = %tmp_path,
                    target_file = %path,
                    error = %e,
                    "failed to rename temporary file to target"
                );
                let _ = std::fs::remove_file(&tmp_path);
                metrics::record_db_operation("persist_data", false, start.elapsed().as_secs_f64());
                Err(e.into())
            }
        }
    }

    /// 获取所有用户信息
    pub fn get_all_users(&self) -> Vec<UserInfo> {
        let map = self.store.read();
        let mut users: Vec<(usize, UserInfo)> = map
            .iter()
            .map(|(username, user_data)| {
                (
                    user_data.order,
                    UserInfo {
                        username: username.clone(),
                        urls: user_data.urls.clone(),
                    },
                )
            })
            .collect();
        users.sort_by_key(|(order, _)| *order);
        users.into_iter().map(|(_, user)| user).collect()
    }
}
