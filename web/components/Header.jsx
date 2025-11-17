import React, { useContext } from 'react';
import AuthContext from '../context/AuthContext';

function Header({ onSettingsClick }) {
  const { onLogout } = useContext(AuthContext);

  const handleLogout = () => {
    if (window.confirm('确定要退出登录吗？')) {
      onLogout();
    }
  };

  return (
    <header className="header">
      <div className="header-container">
        <h1 className="header-title">多链接管理服务</h1>
        <div className="header-actions">
          <button
            className="btn-secondary"
            onClick={onSettingsClick}
            title="账号设置"
          >
            ⚙️ 设置
          </button>
          <button
            className="btn-secondary"
            onClick={handleLogout}
            title="退出登录"
          >
            退出
          </button>
        </div>
      </div>
    </header>
  );
}

export default Header;
