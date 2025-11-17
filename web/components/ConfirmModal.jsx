import React from 'react';

function ConfirmModal({ title, message, onConfirm, onCancel }) {
  return (
    <div className="modal-overlay">
      <div className="modal-content confirm-modal">
        <div className="modal-header">
          <h3>{title}</h3>
        </div>

        <div className="modal-body">
          <p className="confirm-message">{message}</p>
        </div>

        <div className="modal-actions">
          <button
            className="btn-secondary"
            onClick={onCancel}
          >
            取消
          </button>
          <button
            className="btn-danger"
            onClick={onConfirm}
          >
            确定
          </button>
        </div>
      </div>
    </div>
  );
}

export default ConfirmModal;
