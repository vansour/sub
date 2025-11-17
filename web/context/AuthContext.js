import React from 'react';

const AuthContext = React.createContext({
  isAuthenticated: false,
  onLogin: () => {},
  onLogout: () => {},
  token: null,
});

export default AuthContext;
