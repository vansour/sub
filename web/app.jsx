import React, { useState, useEffect, useCallback } from 'react';
import './style.css';
import AuthContext from './context/AuthContext';
import MainLayout from './layouts/MainLayout';
import LoginPage from './pages/LoginPage';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // 检查认证状态
    const token = localStorage.getItem('auth_token');
    if (token) {
      setIsAuthenticated(true);
    }
    setLoading(false);
  }, []);

  const handleLogin = useCallback((token) => {
    localStorage.setItem('auth_token', token);
    setIsAuthenticated(true);
  }, []);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('auth_token');
    setIsAuthenticated(false);
  }, []);

  if (loading) {
    return <div className="loading-container">加载中...</div>;
  }

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        onLogin: handleLogin,
        onLogout: handleLogout,
      }}
    >
      {isAuthenticated ? <MainLayout /> : <LoginPage />}
    </AuthContext.Provider>
  );
}

export default App;
