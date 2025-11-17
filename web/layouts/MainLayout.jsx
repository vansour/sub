import React, { useState } from 'react';
import UserList from '../components/UserList';
import Header from '../components/Header';
import SettingsModal from '../components/SettingsModal';

function MainLayout() {
  const [showSettings, setShowSettings] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handleUserUpdated = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  return (
    <div className="main-layout">
      <Header onSettingsClick={() => setShowSettings(true)} />
      <div className="container">
        <UserList key={refreshTrigger} onUserUpdated={handleUserUpdated} />
      </div>
      {showSettings && (
        <SettingsModal
          onClose={() => setShowSettings(false)}
          onSettingsSaved={handleUserUpdated}
        />
      )}
    </div>
  );
}

export default MainLayout;
