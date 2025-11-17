import React, { useState, useEffect } from 'react';
import { fetchUsers, reorderUsers, ApiError } from '../services/api';
import { useNotification } from '../context/NotificationContext';
import UserTable from './UserTable';
import UserModal from './UserModal';
import QRModal from './QRModal';
import ConfirmModal from './ConfirmModal';

function UserList({ onUserUpdated }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [showQR, setShowQR] = useState(null);
  const [confirmDialog, setConfirmDialog] = useState(null);
  const [draggedUser, setDraggedUser] = useState(null);
  const { showNotification } = useNotification();

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchUsers();
      setUsers(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('加载用户列表失败');
      }
      showNotification(
        err instanceof ApiError ? err.message : '加载失败',
        'error'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleAddUser = () => {
    setEditingUser(null);
    setShowModal(true);
  };

  const handleEditUser = (user) => {
    setEditingUser(user);
    setShowModal(true);
  };

  const handleViewQR = (user) => {
    const userUrl = `${window.location.origin}/${user.username}`;
    setShowQR({ username: user.username, url: userUrl });
  };

  const handleDeleteUser = (user) => {
    setConfirmDialog({
      title: '确认删除',
      message: `确定要删除用户 "${user.username}" 吗？`,
      onConfirm: async () => {
        try {
          const { deleteUser } = await import('../services/api');
          await deleteUser(user.username);
          showNotification(`用户 "${user.username}" 已删除`, 'success');
          loadUsers();
          onUserUpdated();
        } catch (err) {
          showNotification(
            err instanceof ApiError ? err.message : '删除失败',
            'error'
          );
        }
      },
    });
  };

  const handleUserSaved = async () => {
    setShowModal(false);
    await loadUsers();
    onUserUpdated();
  };

  const handleDragStart = (user) => {
    setDraggedUser(user);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = async (targetUser) => {
    if (!draggedUser || draggedUser.username === targetUser.username) {
      return;
    }

    // 重新排序本地数据
    const draggedIndex = users.findIndex(
      (u) => u.username === draggedUser.username
    );
    const targetIndex = users.findIndex(
      (u) => u.username === targetUser.username
    );

    if (draggedIndex === -1 || targetIndex === -1) return;

    const newUsers = [...users];
    newUsers.splice(draggedIndex, 1);
    newUsers.splice(targetIndex, 0, draggedUser);

    setUsers(newUsers);

    // 发送到服务器
    try {
      const usernames = newUsers.map((u) => u.username);
      await reorderUsers(usernames);
      showNotification('顺序已保存', 'success');
    } catch (err) {
      showNotification('保存顺序失败，请重试', 'error');
      loadUsers(); // 刷新列表
    }
  };

  if (loading) {
    return <div className="loading-state"><div className="loading-spinner"></div><p>加载中...</p></div>;
  }

  if (error) {
    return (
      <div className="error-state">
        <div className="error-icon">⚠️</div>
        <p className="error-message">{error}</p>
        <button className="retry-btn" onClick={loadUsers}>
          重新加载
        </button>
      </div>
    );
  }

  return (
    <div className="user-list-container">
      <div className="section-header">
        <h2>用户列表</h2>
        <button className="btn-primary" onClick={handleAddUser}>
          + 添加用户
        </button>
      </div>

      {users.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <p className="empty-message">暂无用户</p>
          <p className="empty-hint">
            点击右上角"添加用户"按钮创建第一个用户
          </p>
        </div>
      ) : (
        <UserTable
          users={users}
          onDragStart={handleDragStart}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onView={handleViewQR}
          onEdit={handleEditUser}
          onDelete={handleDeleteUser}
        />
      )}

      {showModal && (
        <UserModal
          user={editingUser}
          onClose={() => setShowModal(false)}
          onSaved={handleUserSaved}
        />
      )}

      {showQR && (
        <QRModal
          username={showQR.username}
          url={showQR.url}
          onClose={() => setShowQR(null)}
        />
      )}

      {confirmDialog && (
        <ConfirmModal
          title={confirmDialog.title}
          message={confirmDialog.message}
          onConfirm={confirmDialog.onConfirm}
          onCancel={() => setConfirmDialog(null)}
        />
      )}
    </div>
  );
}

export default UserList;
