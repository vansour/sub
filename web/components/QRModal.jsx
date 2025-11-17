import React, { useEffect, useRef } from 'react';
import { useNotification } from '../context/NotificationContext';

function QRModal({ username, url, onClose }) {
  const qrContainerRef = useRef(null);
  const linkInputRef = useRef(null);
  const { showNotification } = useNotification();

  useEffect(() => {
    // 动态加载 QRCode 库
    if (typeof QRCode === 'undefined') {
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js';
      script.onload = generateQR;
      document.head.appendChild(script);
    } else {
      generateQR();
    }
  }, []);

  const generateQR = () => {
    if (!qrContainerRef.current) return;

    // 清空之前的内容
    qrContainerRef.current.innerHTML = '';

    try {
      // eslint-disable-next-line no-undef
      new QRCode(qrContainerRef.current, {
        text: url,
        width: 256,
        height: 256,
        colorDark: '#000000',
        colorLight: '#ffffff',
        // eslint-disable-next-line no-undef
        correctLevel: QRCode.CorrectLevel.H,
      });
    } catch (error) {
      console.error('生成二维码失败:', error);
      showNotification('生成二维码失败', 'error');
    }
  };

  const handleCopyLink = () => {
    const text = linkInputRef.current.value;

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        showNotification('链接已复制到剪贴板', 'success');
      });
    } else {
      // 降级方案
      linkInputRef.current.select();
      linkInputRef.current.setSelectionRange(0, 99999);
      try {
        document.execCommand('copy');
        showNotification('链接已复制到剪贴板', 'success');
      } catch {
        showNotification('复制失败，请手动复制', 'error');
      }
    }
  };

  const handleQRClick = () => {
    handleCopyLink();
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content qr-modal">
        <div className="modal-header">
          <h3>用户链接 - {username}</h3>
          <button className="close-btn" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-body qr-content">
          <div
            ref={qrContainerRef}
            className="qr-code"
            onClick={handleQRClick}
            style={{ cursor: 'pointer' }}
          />

          <div className="qr-link-group">
            <input
              ref={linkInputRef}
              type="text"
              value={url}
              readOnly
              className="qr-link-input"
            />
            <button
              className="btn-primary"
              onClick={handleCopyLink}
            >
              复制链接
            </button>
          </div>

          <p className="qr-hint">点击二维码或"复制链接"按钮可复制用户链接</p>
        </div>
      </div>
    </div>
  );
}

export default QRModal;
