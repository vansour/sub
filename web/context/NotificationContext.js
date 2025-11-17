import React, { useCallback, useState } from 'react';

export const NotificationContext = React.createContext({
  showNotification: () => {},
});

export function useNotification() {
  const context = React.useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within NotificationProvider');
  }
  return context;
}

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);

  const showNotification = useCallback(
    (message, type = 'info', duration = 3000) => {
      const id = Date.now();
      const notification = { id, message, type };

      setNotifications((prev) => [...prev, notification]);

      if (duration > 0) {
        setTimeout(() => {
          setNotifications((prev) =>
            prev.filter((n) => n.id !== id)
          );
        }, duration);
      }

      return id;
    },
    []
  );

  return (
    <NotificationContext.Provider value={{ showNotification }}>
      {children}
      <NotificationContainer notifications={notifications} />
    </NotificationContext.Provider>
  );
}

function NotificationContainer({ notifications }) {
  return (
    <div className="notification-container">
      {notifications.map((notification) => (
        <div
          key={notification.id}
          className={`notification notification-${notification.type}`}
        >
          {notification.message}
        </div>
      ))}
    </div>
  );
}
