// 验证用户名是否合法
pub fn is_valid_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 64 {
        return false;
    }
    username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}
