const base = window.location.origin;

// 认证检查
function checkAuth() {
	const token = localStorage.getItem('auth_token');
	if (!token && window.location.pathname !== '/static/login.html') {
		window.location.href = '/static/login.html';
		return false;
	}
	return true;
}

// 获取认证 header
function getAuthHeader() {
	const token = localStorage.getItem('auth_token');
	return token ? { 'Authorization': `Bearer ${token}` } : {};
}

// 处理 API 错误（如401未授权）
function handleApiError(resp) {
	if (resp.status === 401) {
		localStorage.removeItem('auth_token');
		window.location.href = '/static/login.html';
		return true;
	}
	return false;
}

// 退出登录
function logout() {
	localStorage.removeItem('auth_token');
	window.location.href = '/static/login.html';
}

// 页面加载时检查认证
checkAuth();

// 统一的 API 请求函数
async function apiRequest(url, options = {}) {
	const headers = {
		...getAuthHeader(),
		...options.headers
	};
	
	const resp = await fetch(url, { ...options, headers });
	
	if (handleApiError(resp)) {
		throw new Error('Unauthorized');
	}
	
	return resp;
}

// 通知系统
function showNotification(message, type = 'info') {
	const notification = document.getElementById('notification');
	notification.textContent = message;
	notification.className = `notification notification-${type} show`;
	
	setTimeout(() => {
		notification.classList.remove('show');
	}, 3000);
}

// 二维码功能
let currentQRCode = null;

function showQRCode(username, url) {
	// 检查 QRCode 库是否加载
	if (typeof QRCode === 'undefined') {
		showNotification('二维码功能加载中，请稍后再试', 'warning');
		return;
	}
	
	const modal = document.getElementById('qrModal');
	const qrContainer = document.getElementById('qrcode');
	const linkInput = document.getElementById('qrLink');
	const title = document.getElementById('qrTitle');
	
	// 清空之前的二维码
	qrContainer.innerHTML = '';
	
	try {
		// 生成新二维码
		currentQRCode = new QRCode(qrContainer, {
			text: url,
			width: 256,
			height: 256,
			colorDark: '#000000',
			colorLight: '#ffffff',
			correctLevel: QRCode.CorrectLevel.H
		});
		
		// 设置链接和标题
		linkInput.value = url;
		title.textContent = `用户: ${username}`;
		
		// 给二维码添加点击复制功能
		qrContainer.style.cursor = 'pointer';
		qrContainer.onclick = () => copyLink();
		
		modal.style.display = 'flex';
	} catch (error) {
		console.error('生成二维码失败:', error);
		showNotification('生成二维码失败', 'error');
	}
}

function closeQRModal() {
	const modal = document.getElementById('qrModal');
	modal.style.display = 'none';
}

function copyLink() {
	const linkInput = document.getElementById('qrLink');
	const textToCopy = linkInput.value;
	
	// 优先使用现代 Clipboard API
	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(textToCopy)
			.then(() => {
				showNotification('链接已复制到剪贴板', 'success');
			})
			.catch(err => {
				console.error('复制失败:', err);
				// 降级到旧方法
				fallbackCopyText(linkInput);
			});
	} else {
		// 对于不支持 Clipboard API 的浏览器，使用降级方案
		fallbackCopyText(linkInput);
	}
}

// 降级复制方案（用于旧浏览器或非 HTTPS 环境）
function fallbackCopyText(input) {
	try {
		input.select();
		input.setSelectionRange(0, 99999); // 移动端兼容
		
		const successful = document.execCommand('copy');
		if (successful) {
			showNotification('链接已复制到剪贴板', 'success');
		} else {
			showNotification('复制失败，请手动复制', 'error');
		}
	} catch (err) {
		console.error('降级复制方法也失败:', err);
		showNotification('复制失败，请手动复制', 'error');
		// 保持输入框选中状态，方便用户手动复制
		input.focus();
	}
}

// 确认弹窗
let confirmCallback = null;

function showConfirmModal(message, onConfirm) {
	const modal = document.getElementById('confirmModal');
	const messageEl = document.getElementById('confirmMessage');
	const okBtn = document.getElementById('confirmOkBtn');
	
	messageEl.textContent = message;
	confirmCallback = onConfirm;
	
	// 移除旧的事件监听器
	okBtn.replaceWith(okBtn.cloneNode(true));
	const newOkBtn = document.getElementById('confirmOkBtn');
	
	newOkBtn.addEventListener('click', () => {
		if (confirmCallback) {
			confirmCallback();
			confirmCallback = null;
		}
		closeConfirmModal();
	});
	
	modal.style.display = 'flex';
}

function closeConfirmModal() {
	const modal = document.getElementById('confirmModal');
	modal.style.display = 'none';
	confirmCallback = null;
}

// 弹窗控制
let isEditMode = false;
let originalUsername = '';

function openModal(isEdit = false) {
	const modal = document.getElementById("modal");
	const title = document.getElementById("modalTitle");
	
	isEditMode = isEdit;
	title.textContent = isEdit ? "编辑用户" : "添加用户";
	modal.style.display = "flex";
}

function closeModal() {
	const modal = document.getElementById("modal");
	
	modal.style.display = "none";
	isEditMode = false;
	originalUsername = '';
	document.getElementById("form").reset();
	document.getElementById("result").style.display = "none";
}

// 添加用户按钮
document.getElementById("addUserBtn").addEventListener("click", () => {
	openModal(false);
});

// 显示错误状态页面
function showErrorState(container, message, showRetry = true) {
	const retryButton = showRetry
		? '<button class="retry-btn" onclick="loadUserList()">重新加载</button>'
		: '';
	
	container.innerHTML = `
		<div class="error-state">
			<div class="error-icon">⚠️</div>
			<p class="error-message">${message}</p>
			${retryButton}
		</div>
	`;
}

// 显示空状态页面
function showEmptyState(container) {
	container.innerHTML = `
		<div class="empty-state">
			<div class="empty-icon">📋</div>
			<p class="empty-message">暂无用户</p>
			<p class="empty-hint">点击右上角"添加用户"按钮创建第一个用户</p>
		</div>
	`;
}

// 显示加载状态
function showLoadingState(container) {
	container.innerHTML = `
		<div class="loading-state">
			<div class="loading-spinner"></div>
			<p>加载中...</p>
		</div>
	`;
}

// 加载用户列表
async function loadUserList() {
	const listDiv = document.getElementById("userList");
	showLoadingState(listDiv);
	
	try {
		const resp = await apiRequest("/api/users");
		
		if (!resp.ok) {
			if (resp.status === 404) {
				throw new Error("API 接口不存在");
			} else if (resp.status >= 500) {
				throw new Error("服务器错误，请稍后重试");
			} else {
				throw new Error(`请求失败: ${resp.status}`);
			}
		}
		
		const data = await resp.json();
		displayUserList(data.users);
	} catch (error) {
		console.error("加载用户列表失败:", error);
		showErrorState(
			listDiv,
			`加载失败: ${error.message}`,
			true
		);
		showNotification('加载用户列表失败，请重试', 'error');
	}
}

// 存储用户顺序
let userOrder = [];

// 显示用户列表
function displayUserList(users) {
	const listDiv = document.getElementById("userList");
	if (users.length === 0) {
		showEmptyState(listDiv);
		return;
	}

	// 保存用户顺序
	userOrder = users.map(u => u.username);

	let html = '<table><thead><tr><th class="drag-col"></th><th>用户名</th><th>链接</th><th>操作</th></tr></thead><tbody id="sortable-tbody">';
	for (const user of users) {
		const userUrl = base + "/" + user.username;
		html += `
			<tr draggable="true" data-username="${user.username}">
				<td class="drag-handle" title="拖拽调整顺序">⋮⋮</td>
				<td><a href="${userUrl}" target="_blank" class="username-link">${user.username}</a></td>
				<td class="url-cell">${user.urls.length} 个链接</td>
				<td class="action-cell">
					<button class="btn-view" data-username="${user.username}" data-urls='${JSON.stringify(user.urls)}'>查看</button>
					<button class="btn-edit" data-username="${user.username}" data-urls='${JSON.stringify(user.urls)}'>编辑</button>
					<button class="btn-delete" data-username="${user.username}">删除</button>
				</td>
			</tr>
		`;
	}
	html += "</tbody></table>"
	listDiv.innerHTML = html;

	// 初始化拖拽功能
	initDragAndDrop();
	
	// 添加事件监听器
	document.querySelectorAll(".btn-view").forEach(btn => {
		btn.addEventListener("click", function() {
			const username = this.dataset.username;
			const userUrl = base + "/" + username;
			showQRCode(username, userUrl);
		});
	});
	
	document.querySelectorAll(".btn-edit").forEach(btn => {
		btn.addEventListener("click", function() {
			const username = this.dataset.username;
			const urls = JSON.parse(this.dataset.urls);
			editUser(username, urls);
		});
	});
	
	document.querySelectorAll(".btn-delete").forEach(btn => {
		btn.addEventListener("click", function() {
			const username = this.dataset.username;
			deleteUser(username);
		});
	});
}

// 拖拽功能
let draggedElement = null;

function initDragAndDrop() {
	const rows = document.querySelectorAll('#sortable-tbody tr[draggable="true"]');
	
	rows.forEach(row => {
		row.addEventListener('dragstart', handleDragStart);
		row.addEventListener('dragover', handleDragOver);
		row.addEventListener('drop', handleDrop);
		row.addEventListener('dragend', handleDragEnd);
		row.addEventListener('dragenter', handleDragEnter);
		row.addEventListener('dragleave', handleDragLeave);
	});
}

function handleDragStart(e) {
	draggedElement = this;
	this.classList.add('dragging');
	e.dataTransfer.effectAllowed = 'move';
	e.dataTransfer.setData('text/html', this.innerHTML);
}

function handleDragOver(e) {
	if (e.preventDefault) {
		e.preventDefault();
	}
	e.dataTransfer.dropEffect = 'move';
	return false;
}

function handleDragEnter(e) {
	if (this !== draggedElement) {
		this.classList.add('drag-over');
	}
}

function handleDragLeave(e) {
	this.classList.remove('drag-over');
}

function handleDrop(e) {
	if (e.stopPropagation) {
		e.stopPropagation();
	}
	
	if (draggedElement !== this) {
		// 获取所有行
		const tbody = document.getElementById('sortable-tbody');
		const rows = Array.from(tbody.querySelectorAll('tr'));
		
		// 找到拖拽元素和目标元素的位置
		const draggedIndex = rows.indexOf(draggedElement);
		const targetIndex = rows.indexOf(this);
		
		// 重新排序
		if (draggedIndex < targetIndex) {
			tbody.insertBefore(draggedElement, this.nextSibling);
		} else {
			tbody.insertBefore(draggedElement, this);
		}
		
		// 更新用户顺序数组
		updateUserOrder();
	}
	
	this.classList.remove('drag-over');
	return false;
}

function handleDragEnd(e) {
	this.classList.remove('dragging');
	
	// 移除所有拖拽样式
	const rows = document.querySelectorAll('#sortable-tbody tr');
	rows.forEach(row => {
		row.classList.remove('drag-over');
	});
}

function updateUserOrder() {
	const tbody = document.getElementById('sortable-tbody');
	const rows = tbody.querySelectorAll('tr');
	const newOrder = Array.from(rows).map(row => row.dataset.username);
	
	// 检查顺序是否改变
	const orderChanged = JSON.stringify(newOrder) !== JSON.stringify(userOrder);
	
	if (orderChanged) {
		userOrder = newOrder;
		console.log('用户顺序已更新:', userOrder);
		
		// 发送到服务器保存
		saveUserOrder(newOrder);
	}
}

// 保存用户顺序到服务器
async function saveUserOrder(usernames) {
	try {
		const resp = await apiRequest('/api/reorder', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ usernames })
		});
		
		if (resp.ok) {
			showNotification('顺序已保存', 'success');
		} else {
			console.error('保存顺序失败:', resp.status);
			showNotification('保存顺序失败', 'error');
		}
	} catch (error) {
		console.error('保存顺序时出错:', error);
		showNotification('保存顺序失败', 'error');
	}
}

// 编辑用户
function editUser(username, urls) {
	originalUsername = username; // 保存原始用户名
	document.getElementById("username").value = username;
	document.getElementById("urls").value = urls.join("\n");
	openModal(true);
}

// 删除用户
async function deleteUser(username) {
	showConfirmModal(`确定要删除用户 "${username}" 吗？`, async () => {
		try {
			const resp = await apiRequest(`/api/delete/${username}`, {
				method: "DELETE",
			});
			
			if (!resp.ok) {
				showNotification('删除失败: ' + resp.status, 'error');
				return;
			}
			
			console.log("删除成功:", username);
			loadUserList();
			showNotification(`用户 "${username}" 已删除`, 'success');
		} catch (error) {
			console.error("删除失败:", error);
			showNotification('删除失败: ' + error.message, 'error');
		}
	});
}

// 页面加载时获取用户列表
loadUserList();

// 表单提交
document.getElementById("form").addEventListener("submit", async (e) => {
	e.preventDefault();
	console.log("表单提交事件触发");
	
	const username = document.getElementById("username").value.trim();
	const lines = document
		.getElementById("urls")
		.value.split("\n")
		.map((x) => x.trim())
		.filter((x) => x.length > 0);

	console.log("用户名:", username);
	console.log("解析的链接:", lines);

	if (!username) {
		showNotification('请输入用户名', 'warning');
		return;
	}

	if (lines.length === 0) {
		showNotification('请至少输入一个链接', 'warning');
		return;
	}

	try {
		// 如果是编辑模式且用户名改变了，先删除旧用户
		if (isEditMode && originalUsername && originalUsername !== username) {
			console.log(`用户名已改变，从 "${originalUsername}" 到 "${username}"，删除旧用户`);
			try {
				const deleteResp = await apiRequest(`/api/delete/${originalUsername}`, {
					method: "DELETE",
				});
				if (!deleteResp.ok) {
					console.warn(`删除旧用户 "${originalUsername}" 失败:`, deleteResp.status);
					// 继续创建新用户，即使删除失败
				}
			} catch (deleteError) {
				console.error("删除旧用户时出错:", deleteError);
				// 继续创建新用户
			}
		}
		
		console.log("发送请求到 /api/create");
		// 编辑模式下自动允许覆盖
		const requestBody = {
			username,
			urls: lines,
			allow_overwrite: isEditMode
		};
		console.log("请求体:", requestBody);
		const resp = await apiRequest("/api/create", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(requestBody),
		});

		console.log("响应状态:", resp.status);

		if (!resp.ok) {
			let errorMessage = '创建失败';
			try {
				const errorData = await resp.json();
				errorMessage = errorData.error || errorMessage;
				if (errorData.hint) {
					errorMessage += ` (${errorData.hint})`;
				}
			} catch (e) {
				// 如果响应不是 JSON，使用状态码
				errorMessage = `创建失败: HTTP ${resp.status}`;
			}
			console.error("创建失败:", errorMessage);
			showNotification(errorMessage, 'error');
			return;
		}

		const data = await resp.json();
		console.log("创建成功:", data);
		
		// 重新加载用户列表
		loadUserList();
		
		// 编辑模式下直接关闭弹窗，不显示成功提示
		if (isEditMode) {
			showNotification(`用户 "${data.username}" 已更新`, 'success');
			closeModal();
		} else {
			// 添加模式下显示用户链接
			const userUrl = base + "/" + data.username;
			const box = document.getElementById("result");
			box.style.display = "block";
			box.innerHTML =
				`<strong>✓ 成功！</strong> 用户链接：<a href="${userUrl}" target="_blank">${userUrl}</a>`;
			
			// 2秒后关闭弹窗
			setTimeout(() => {
				closeModal();
			}, 2000);
		}
	} catch (error) {
		console.error("请求异常:", error);
		showNotification('请求失败: ' + error.message, 'error');
	}
});

// 设置按钮
document.getElementById("settingsBtn").addEventListener("click", () => {
	document.getElementById("settingsModal").style.display = "flex";
});

// 退出按钮
document.getElementById("logoutBtn").addEventListener("click", () => {
	logout();
});

// 关闭设置弹窗
function closeSettingsModal() {
	document.getElementById("settingsModal").style.display = "none";
	document.getElementById("settingsForm").reset();
}

// 设置表单提交
document.getElementById("settingsForm").addEventListener("submit", async (e) => {
	e.preventDefault();
	
	const oldPassword = document.getElementById("oldPassword").value;
	const newUsername = document.getElementById("newUsername").value;
	const newPassword = document.getElementById("newPassword").value;
	const confirmPassword = document.getElementById("confirmPassword").value;
	
	if (newPassword !== confirmPassword) {
		showNotification('两次输入的密码不一致', 'error');
		return;
	}
	
	try {
		const resp = await apiRequest('/api/change-password', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				old_password: oldPassword,
				new_username: newUsername,
				new_password: newPassword
			})
		});
		
		if (resp.ok) {
			showNotification('设置已保存，请重新登录', 'success');
			setTimeout(() => {
				logout();
			}, 1500);
		} else {
			const error = await resp.json();
			showNotification(error.error || '保存失败', 'error');
		}
	} catch (error) {
		showNotification('保存失败: ' + error.message, 'error');
	}
});
