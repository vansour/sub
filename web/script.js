const $ = sel => document.querySelector(sel);

// 全局 API 包装器
async function api(path, opts = {}) {
  opts.credentials = 'include'; // 发送 Cookie

  try {
    const res = await fetch(path, opts);

    // 401 未授权 -> 显示登录界面，隐藏主应用
    if (res.status === 401) {
      showLoginScreen();
      return null;
    }

    const text = await res.text();
    try { return JSON.parse(text); } catch (e) { return text; }
  } catch (e) {
    console.error("API Error:", e);
    return null;
  }
}

// --- 界面切换逻辑 ---

function showLoginScreen() {
  $('#login-screen').classList.remove('hidden');
  $('#app-content').classList.add('hidden'); // 完全隐藏主应用 DOM
  $('#modal-overlay').classList.add('hidden');
  $('#login-username').focus();
}

function showAppScreen() {
  $('#login-screen').classList.add('hidden');
  $('#app-content').classList.remove('hidden');
  renderUsers();
}

// --- 认证逻辑 ---

async function checkAuth() {
  const res = await fetch('/api/auth/me');
  if (res.ok) {
    showAppScreen();
  } else {
    showLoginScreen();
  }
}

async function doLogin(e) {
  e.preventDefault();
  const username = $('#login-username').value;
  const password = $('#login-password').value;
  const btn = e.target.querySelector('button');

  const originalText = btn.innerText;
  btn.innerText = '登录中...';
  btn.disabled = true;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (res.ok) {
      $('#login-password').value = '';
      $('#login-status').innerText = '';
      showAppScreen();
    } else {
      $('#login-status').innerText = '登录失败：用户名或密码错误';
      $('.login-card').animate([
        { transform: 'translateX(0)' },
        { transform: 'translateX(-5px)' },
        { transform: 'translateX(5px)' },
        { transform: 'translateX(0)' }
      ], { duration: 300 });
    }
  } finally {
    btn.innerText = originalText;
    btn.disabled = false;
  }
}

async function doLogout() {
  await api('/api/auth/logout', { method: 'POST' });
  showLoginScreen();
}

// --- 账号管理逻辑 ---
async function doUpdateAccount() {
  const currentPassword = $('#account-current-password').value.trim();
  const newUsername = $('#account-username').value.trim();
  const newPassword = $('#account-password').value.trim();
  const btn = $('#modal-account-save');
  const status = $('#modal-account-status');

  if (!currentPassword) {
    status.innerText = "请输入当前密码";
    return;
  }
  if (!newUsername || !newPassword) {
    status.innerText = "新用户名和密码不能为空";
    return;
  }

  btn.disabled = true;
  btn.innerText = "更新中...";

  const res = await fetch('/api/auth/account', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      current_password: currentPassword,
      new_username: newUsername,
      new_password: newPassword
    })
  });

  if (res.ok) {
    alert("账号更新成功，请重新登录");
    window.location.reload();
  } else {
    const txt = await res.text();
    status.innerText = "更新失败: " + txt;
    btn.disabled = false;
    btn.innerText = "保存更改";
  }
}


// --- 拖拽排序辅助 ---
function getDragAfterElement(container, y, selector = 'tr:not(.dragging)') {
  const draggableElements = [...container.querySelectorAll(selector)];
  let closest = { offset: Number.NEGATIVE_INFINITY, element: null };
  for (const child of draggableElements) {
    const box = child.getBoundingClientRect();
    const offset = y - box.top - box.height / 2;
    if (offset < 0 && offset > closest.offset) {
      closest = { offset, element: child };
    }
  }
  return closest.element;
}

async function saveOrder() {
  const rows = Array.from(document.querySelectorAll('#user-list tr'));
  const order = rows.map(r => r.dataset.username).filter(Boolean);
  if (!order.length) return;
  await api('/api/users/order', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ order }) });
}

// --- 订阅源链接行管理 ---

function createLinkItem(url = '') {
  const div = document.createElement('div');
  div.className = 'link-item';
  div.setAttribute('draggable', 'true');

  div.innerHTML = `
    <div class="drag-handle">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <circle cx="9" cy="6" r="1.5"></circle>
        <circle cx="9" cy="12" r="1.5"></circle>
        <circle cx="9" cy="18" r="1.5"></circle>
        <circle cx="15" cy="6" r="1.5"></circle>
        <circle cx="15" cy="12" r="1.5"></circle>
        <circle cx="15" cy="18" r="1.5"></circle>
      </svg>
    </div>
    <div class="link-input-wrapper">
      <input type="text" placeholder="https://example.com/rss" value="${url}" />
    </div>
    <button class="btn btn-text btn-sm btn-remove-link" title="移除">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
    </button>
  `;

  // 移除逻辑
  div.querySelector('.btn-remove-link').onclick = () => div.remove();

  // 拖拽逻辑 (内部)
  div.addEventListener('dragstart', (e) => {
    const handle = div.querySelector('.drag-handle');
    if (!handle.contains(e.target)) {
      e.preventDefault();
      return;
    }
    div.classList.add('dragging');
  });
  div.addEventListener('dragend', () => {
    div.classList.remove('dragging');
  });

  return div;
}

function renderLinkContainer(links = []) {
  const container = $('#link-list-container');
  container.innerHTML = '';
  links.forEach(url => container.appendChild(createLinkItem(url)));
  if (links.length === 0) {
    container.appendChild(createLinkItem(''));
  }
}

// 绑定链接列表的拖拽目标
function attachLinkListDnD() {
  const container = $('#link-list-container');
  container.addEventListener('dragover', (e) => {
    e.preventDefault();
    const dragging = container.querySelector('.link-item.dragging');
    if (!dragging) return;
    const after = getDragAfterElement(container, e.clientY, '.link-item:not(.dragging)');
    if (after == null) container.appendChild(dragging);
    else container.insertBefore(dragging, after);
  });
}

// --- 核心渲染逻辑 ---

async function renderUsers() {
  const list = await api('/api/users');
  const tbody = $('#user-list');
  tbody.innerHTML = '';

  if (!Array.isArray(list)) { return; }

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" style="text-align:center; padding: 4rem 1rem;"><div class="text-muted" style="margin-bottom: 1rem;"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.5;"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg></div><div class="text-muted">暂无用户，点击右上角新建</div></td></tr>';
    return;
  }

  list.forEach(u => {
    const tr = document.createElement('tr');
    tr.setAttribute('draggable', 'true');
    tr.dataset.username = u;

    // 1. 用户名列 (仅显示用户名，不显示链接)
    const tdName = document.createElement('td');
    const nameDiv = document.createElement('div');
    nameDiv.className = 'user-name-cell';
    nameDiv.textContent = u;
    tdName.appendChild(nameDiv);

    // 2. 操作列
    const tdActions = document.createElement('td');
    const actionGroup = document.createElement('div');
    actionGroup.className = 'action-group';

    const fullUrl = window.location.origin + '/' + encodeURIComponent(u);

    // (1) 复制按钮 (第一位)
    const btnCopy = document.createElement('button');
    btnCopy.className = 'btn btn-sm btn-outline';
    btnCopy.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> 复制`;
    btnCopy.onclick = async () => {
      try {
        await navigator.clipboard.writeText(fullUrl);
        const originalHTML = btnCopy.innerHTML;
        btnCopy.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> 已复制`;
        btnCopy.classList.add('btn-success-state');
        setTimeout(() => {
          btnCopy.innerHTML = originalHTML;
          btnCopy.classList.remove('btn-success-state');
        }, 1500);
      } catch (err) {
        console.error('Copy failed', err);
        alert("复制失败，请手动复制");
      }
    };



    // (2) 编辑按钮
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn-sm btn-outline';
    btnEdit.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg> 编辑`;
    btnEdit.onclick = () => openEditModal(u);

    // (3) 打开按钮
    const btnOpen = document.createElement('button');
    btnOpen.className = 'btn btn-sm btn-outline';
    btnOpen.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg> 打开`;
    btnOpen.onclick = () => window.open(fullUrl, '_blank');

    // (4) 删除按钮 (红色常驻)
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn-sm btn-danger-soft';
    btnDel.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> 删除`;
    btnDel.onclick = () => openDeleteModal(u);

    actionGroup.appendChild(btnCopy);

    actionGroup.appendChild(btnEdit);
    actionGroup.appendChild(btnOpen);
    actionGroup.appendChild(btnDel);

    tdActions.appendChild(actionGroup);

    tr.appendChild(tdName);
    tr.appendChild(tdActions);

    // 拖拽逻辑
    tr.addEventListener('dragstart', (ev) => {
      tr.classList.add('dragging');
      ev.dataTransfer.effectAllowed = 'move';
      ev.dataTransfer.setData('text/plain', u);
    });
    tr.addEventListener('dragend', async () => {
      tr.classList.remove('dragging');
      await saveOrder();
    });

    tbody.appendChild(tr);
  });

  // 绑定拖拽容器事件
  if (!tbody.dataset.dragAttached) {
    tbody.dataset.dragAttached = '1';
    tbody.addEventListener('dragover', (e) => {
      e.preventDefault();
      const dragging = tbody.querySelector('tr.dragging');
      if (!dragging) return;
      const after = getDragAfterElement(tbody, e.clientY, 'tr:not(.dragging)');
      if (after == null) tbody.appendChild(dragging);
      else tbody.insertBefore(dragging, after);
    });
  }
}

// --- 模态框逻辑 ---

let _editLoading = false;

function showModal(id) {
  $('#modal-overlay').classList.remove('hidden');
  $(`#${id}`).classList.remove('hidden');
}

function hideModal(id) {
  $('#modal-overlay').classList.add('hidden');
  $(`#${id}`).classList.add('hidden');
}

function openAddModal() {
  $('#modal-form-username').value = '';
  renderLinkContainer([]);
  $('#modal-form-status').innerText = '';
  $('#modal-form').dataset.mode = 'add';
  $('#modal-form-username').removeAttribute('disabled');
  $('#modal-form-title').innerText = '新建订阅用户';
  $('#modal-form-save').innerText = '创建用户';
  showModal('modal-form');
  $('#modal-form-username').focus();
}

async function openEditModal(username) {
  if (_editLoading) return;
  _editLoading = true;

  try {
    const links = await api('/api/users/' + encodeURIComponent(username) + '/links');
    if (links === null) return;

    $('#modal-form-title').innerText = '配置用户: ' + username;
    $('#modal-form').dataset.mode = 'edit';
    $('#modal-form').dataset.user = username;
    $('#modal-form-username').value = username;
    $('#modal-form-username').setAttribute('disabled', 'true');
    $('#modal-form-status').innerText = '';

    if (Array.isArray(links)) {
      renderLinkContainer(links);
    } else {
      renderLinkContainer([]);
    }

    $('#modal-form-save').innerText = '保存更改';
    showModal('modal-form');
  } finally {
    _editLoading = false;
  }
}

function closeAllModals() {
  if (!$('#login-screen').classList.contains('hidden')) return;
  hideModal('modal-form');
  hideModal('modal-delete');
  hideModal('modal-account');
}

async function openDeleteModal(username) {
  $('#modal-delete').dataset.user = username;
  $('#modal-delete-status').innerText = '';
  $('#modal-delete-message').innerHTML = `确定要删除用户 <strong>${username}</strong> 吗？<br><span style="font-size:0.8em">此操作无法撤销</span>`;
  showModal('modal-delete');
}

// --- 初始化 ---

document.addEventListener('DOMContentLoaded', () => {
  checkAuth();

  $('#login-form').addEventListener('submit', doLogin);
  $('#btn-logout').addEventListener('click', doLogout);
  $('#add-user').addEventListener('click', () => openAddModal());

  // 账号管理
  $('#btn-account').addEventListener('click', () => {
    $('#account-username').value = '';
    $('#account-password').value = '';
    $('#account-current-password').value = '';
    $('#modal-account-status').innerText = '';
    $('#modal-account-save').disabled = false;
    $('#modal-account-save').innerText = '保存更改';
    showModal('modal-account');
  });
  $('#modal-account-save').addEventListener('click', doUpdateAccount);

  // 链接列表管理
  $('#btn-add-link').addEventListener('click', () => {
    $('#link-list-container').appendChild(createLinkItem(''));
  });
  attachLinkListDnD();

  // 模态框保存
  $('#modal-form-save').addEventListener('click', async (e) => {
    const btn = e.target;
    const originalText = btn.innerText;
    btn.disabled = true;
    btn.innerText = '处理中...';

    const mode = $('#modal-form').dataset.mode;
    const username = $('#modal-form-username').value.trim();

    // 从 DOM 中收集所有链接
    const linkInputs = document.querySelectorAll('#link-list-container input');
    const arr = Array.from(linkInputs).map(input => input.value.trim()).filter(Boolean);

    if (!username) {
      $('#modal-form-status').innerText = '用户名不能为空';
      btn.disabled = false;
      btn.innerText = originalText;
      return;
    }

    try {
      if (mode === 'add') {
        const res = await api('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });

        if (!res) throw new Error("Network error");
        if (typeof res === 'string' && res.includes('exists')) {
          $('#modal-form-status').innerText = '该用户已存在';
          return;
        }

        if (arr.length > 0) {
          await api('/api/users/' + encodeURIComponent(username) + '/links', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ links: arr }) });
        }
      } else if (mode === 'edit') {
        const orig = $('#modal-form').dataset.user;
        await api('/api/users/' + encodeURIComponent(orig) + '/links', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ links: arr }) });
      }

      hideModal('modal-form');
      await renderUsers();
    } catch (err) {
      console.error(err);
      $('#modal-form-status').innerText = '操作失败，请重试';
    } finally {
      btn.disabled = false;
      btn.innerText = originalText;
    }
  });

  $('#modal-delete-cancel').addEventListener('click', () => hideModal('modal-delete'));
  $('#modal-delete-confirm').addEventListener('click', async () => {
    const user = $('#modal-delete').dataset.user;
    const res = await api('/api/users/' + encodeURIComponent(user), { method: 'DELETE' });
    if (res) { hideModal('modal-delete'); renderUsers(); }
  });

  $('#modal-form-cancel').addEventListener('click', () => hideModal('modal-form'));
  $('#modal-form-cancel-x').addEventListener('click', () => hideModal('modal-form'));
  $('#modal-account-cancel').addEventListener('click', () => hideModal('modal-account'));

  $('#modal-overlay').addEventListener('click', closeAllModals);

  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeAllModals();
  });
});