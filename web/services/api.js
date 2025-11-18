// API 基础配置
const API_BASE = window.location.origin;

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

// 获取认证 header
function getAuthHeaders() {
  const token = localStorage.getItem('auth_token');
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// 处理 API 响应
async function handleResponse(response) {
  if (response.status === 401) {
    localStorage.removeItem('auth_token');
    window.location.href = '/static/login.html';
    throw new ApiError('未授权，请重新登录', 401);
  }

  let data;
  try {
    data = await response.json();
  } catch (e) {
    data = {};
  }

  if (!response.ok) {
    const message = data?.message || data?.error || `请求失败 (${response.status})`;
    throw new ApiError(message, response.status, data);
  }

  return data;
}

// 发送 API 请求
export async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      ...getAuthHeaders(),
      ...options.headers,
    },
  });

  return handleResponse(response);
}

// 登录
export async function login(username, password) {
  const data = await apiRequest('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  // 后端返回格式为 {success: true, data: {token: "..."}}
  return data.data?.token || data.token;
}

// 获取用户列表
export async function fetchUsers() {
  const data = await apiRequest('/api/users');
  // 后端返回格式为 {success: true, data: {users: [...]}}
  return data.data?.users || data.users || [];
}

// 获取用户信息
export async function fetchUserInfo(username) {
  const data = await apiRequest(`/api/info/${username}`);
  // 后端返回格式为 {success: true, data: {username: "...", urls: [...]}}
  return data.data || data;
}

// 创建用户
export async function createUser(username, urls, allowOverwrite = false) {
  const data = await apiRequest('/api/create', {
    method: 'POST',
    body: JSON.stringify({
      username,
      urls,
      allow_overwrite: allowOverwrite,
    }),
  });
  // 后端返回格式为 {success: true, data: {username: "...", ...}}
  return data.data || data;
}

// 删除用户
export async function deleteUser(username) {
  const data = await apiRequest(`/api/delete/${username}`, {
    method: 'DELETE',
  });
  // 后端返回格式为 {success: true, message: "..."}
  return data;
}

// 重新排序用户
export async function reorderUsers(usernames) {
  const data = await apiRequest('/api/reorder', {
    method: 'POST',
    body: JSON.stringify({ usernames }),
  });
  // 后端返回格式为 {success: true, message: "..."}
  return data;
}

// 修改密码
export async function changePassword(oldPassword, newUsername, newPassword) {
  const data = await apiRequest('/api/change-password', {
    method: 'POST',
    body: JSON.stringify({
      old_password: oldPassword,
      new_username: newUsername,
      new_password: newPassword,
    }),
  });
  // 后端返回格式为 {success: true, message: "..."}
  return data;
}

export { ApiError };
