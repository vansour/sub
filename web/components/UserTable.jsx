import React from 'react';

function UserTable({ users, onDragStart, onDragOver, onDrop, onView, onEdit, onDelete }) {
  return (
    <table className="user-table">
      <thead>
        <tr>
          <th className="drag-col"></th>
          <th>用户名</th>
          <th>链接</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        {users.map((user) => (
          <tr
            key={user.username}
            draggable
            onDragStart={() => onDragStart(user)}
            onDragOver={onDragOver}
            onDrop={() => onDrop(user)}
            className="user-row"
          >
            <td className="drag-handle" title="拖拽调整顺序">
              ⋮⋮
            </td>
            <td>
              <a
                href={`${window.location.origin}/${user.username}`}
                target="_blank"
                rel="noopener noreferrer"
                className="username-link"
              >
                {user.username}
              </a>
            </td>
            <td className="url-cell">{user.urls.length} 个链接</td>
            <td className="action-cell">
              <button
                className="btn-view"
                onClick={() => onView(user)}
                title="查看二维码"
              >
                查看
              </button>
              <button
                className="btn-edit"
                onClick={() => onEdit(user)}
                title="编辑用户"
              >
                编辑
              </button>
              <button
                className="btn-delete"
                onClick={() => onDelete(user)}
                title="删除用户"
              >
                删除
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default UserTable;
