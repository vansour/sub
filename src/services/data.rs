use crate::errors::AppResult;
use crate::models::{UserData, UserInfo};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

pub struct DataService {
    store: Arc<RwLock<HashMap<String, UserData>>>,
    data_file_path: String,
}

impl DataService {
    pub fn new(store: Arc<RwLock<HashMap<String, UserData>>>, data_file_path: String) -> Self {
        Self {
            store,
            data_file_path,
        }
    }

    /// 从 data.toml 加载数据到内存
    pub fn load(&self) -> AppResult<()> {
        let path = &self.data_file_path;
        if !std::path::Path::new(path).exists() {
            tracing::info!("data file not found, starting with empty store");
            return Ok(());
        }

        let content = std::fs::read_to_string(path)?;
        let data: toml::Value = toml::from_str(&content)?;

        if let Some(links) = data.get("links").and_then(|v| v.as_array()) {
            let mut map = self.store.write();
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
                        // 读取 order 字段，如果不存在则使用索引
                        let order = link
                            .get("order")
                            .and_then(|v| v.as_integer())
                            .map(|v| v as usize)
                            .unwrap_or(index + 1);

                        map.insert(
                            username.to_string(),
                            UserData {
                                urls: url_list,
                                order,
                            },
                        );
                        tracing::info!("loaded user: {} (order: {})", username, order);
                    }
                }
            }
            tracing::info!("loaded {} users from data file", map.len());
        }

        Ok(())
    }

    /// 将内存中的短链映射写入 data.toml
    /// 使用临时文件 + 原子 rename 确保数据完整性
    pub fn persist(&self) -> AppResult<()> {
        let map = self.store.read();
        let mut items: Vec<(String, UserData)> =
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        // 按 order 排序
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
            std::fs::create_dir_all(parent)?;
        }

        // 使用临时文件写入，然后原子性地 rename
        let tmp_path = format!("{}.tmp.{}", path, std::process::id());
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(toml.as_bytes())?;
            file.sync_all()?; // 确保数据刷新到磁盘
        }

        // 原子性地替换目标文件
        std::fs::rename(&tmp_path, path)?;
        Ok(())
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
        // 按 order 排序
        users.sort_by_key(|(order, _)| *order);
        users.into_iter().map(|(_, user)| user).collect()
    }
}
