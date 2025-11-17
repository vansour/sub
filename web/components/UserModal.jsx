import React, { useState, useEffect } from 'react';
import { createUser, ApiError } from '../services/api';
import { useNotification } from '../context/NotificationContext';

function UserModal({ user, onClose, onSaved }) {
  const [username, setUsername] = useState('');
  const [urls, setUrls] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useNotification();

  useEffect(() => {
    if (user) {
      setUsername(user.username);
      setUrls(user.urls.join('\n'));
    }
  }, [user]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const urlList = urls
      .split('\n')
      .map((url) => url.trim())
      .filter((url) => url.length > 0);

    if (!username.trim()) {
      showNotification('请输入用户名', 'warning');
      setLoading(false);
      return;
    }

    if (urlList.length === 0) {
      showNotification('请至少输入一个链接', 'warning');
      setLoading(false);
      return;
    }

    try {
      await createUser(username, urlList, !!user); // 编辑时允许覆盖
      const action = user ? '已更新' : '已创建';
      showNotification(`用户 "${username}" ${action}`, 'success');
      onSaved();
    } catch (err) {
      if (err instanceof ApiError) {
        showNotification(err.message, 'error');
      } else {
        showNotification('保存失败，请重试', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h3>{user ? '编辑用户' : '添加用户'}</h3>
          <button className="close-btn" onClick={onClose}>
            ×
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label htmlFor="username">用户名</label>
            <input
              id="username"
              type="text"
              placeholder="例如: user1"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="urls">链接列表（每行一个）</label>
            <textarea
              id="urls"
              placeholder="https://example.com/a&#10;https://example.com/b"
              value={urls}
              onChange={(e) => setUrls(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={onClose}
              disabled={loading}
            >
              取消
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
            >
              {loading ? '保存中...' : '保存'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default UserModal;
