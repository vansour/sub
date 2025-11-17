import React, { useState } from 'react';
import { changePassword, ApiError } from '../services/api';
import { useNotification } from '../context/NotificationContext';
import AuthContext from '../context/AuthContext';

function SettingsModal({ onClose, onSettingsSaved }) {
  const [oldPassword, setOldPassword] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useNotification();
  const { onLogout } = React.useContext(AuthContext);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!oldPassword || !newUsername || !newPassword || !confirmPassword) {
      showNotification('请填写所有字段', 'warning');
      return;
    }

    if (newPassword !== confirmPassword) {
      showNotification('两次输入的密码不一致', 'error');
      return;
    }

    setLoading(true);

    try {
      await changePassword(oldPassword, newUsername, newPassword);
      showNotification('设置已保存，请重新登录', 'success');
      setTimeout(() => {
        onLogout();
      }, 1500);
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
          <h3>账号设置</h3>
          <button className="close-btn" onClick={onClose}>
            ×
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label htmlFor="oldPassword">当前密码</label>
            <input
              id="oldPassword"
              type="password"
              placeholder="请输入当前密码"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="newUsername">新用户名</label>
            <input
              id="newUsername"
              type="text"
              placeholder="请输入新用户名"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="newPassword">新密码</label>
            <input
              id="newPassword"
              type="password"
              placeholder="请输入新密码"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">确认新密码</label>
            <input
              id="confirmPassword"
              type="password"
              placeholder="请再次输入新密码"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
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

export default SettingsModal;
