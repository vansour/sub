const $ = sel => document.querySelector(sel);
const $all = sel => Array.from(document.querySelectorAll(sel));

// 移除 URL 参数 API_TOKEN，改用 Cookie 鉴权

async function api(path, opts = {}) {
  // 自动发送凭据 (cookies)
  opts.credentials = 'include';

  const res = await fetch(path, opts);

  // 如果未授权，弹出登录框
  if (res.status === 401) {
    showLoginModal();
    return null;
  }

  const text = await res.text();
  try { return JSON.parse(text); } catch (e) { return text; }
}

function showLoginModal() {
  $('#modal-overlay').classList.remove('hidden');
  $('#modal-login').classList.remove('hidden');
  $('#login-username').focus();
}

async function doLogin(e) {
  e.preventDefault();
  const username = $('#login-username').value;
  const password = $('#login-password').value;

  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  if (res.ok) {
    hideModal('modal-login');
    $('#btn-logout').classList.remove('hidden');
    renderUsers();
  } else {
    $('#login-status').innerText = '登录失败：用户名或密码错误';
  }
}

async function doLogout() {
  await api('/api/auth/logout', { method: 'POST' });
  window.location.reload();
}

async function checkAuth() {
  const res = await fetch('/api/auth/me');
  if (res.ok) {
    $('#btn-logout').classList.remove('hidden');
    renderUsers();
  } else {
    showLoginModal();
  }
}

function getDragAfterElement(container, y) {
  const draggableElements = [...container.querySelectorAll('tr:not(.dragging)')];
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
  try {
    const res = await api('/api/users/order', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ order }) });
    console.log('saved order', res);
  } catch (e) {
    console.warn('failed to save order', e);
  }
}

async function renderUsers() {
  const list = await api('/api/users');
  const tbody = $('#user-list');
  tbody.innerHTML = '';

  // 如果 list 为 null (401) 或非数组，不渲染
  if (!Array.isArray(list)) {
    return;
  }

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" class="notice">没有用户 — 点击上方添加</td></tr>';
    return;
  }

  list.forEach(u => {
    const tr = document.createElement('tr');
    tr.setAttribute('draggable', 'true');
    tr.dataset.username = u;

    // 安全构建 DOM，防止 XSS
    const tdName = document.createElement('td');
    const strong = document.createElement('strong');
    strong.textContent = u;
    tdName.appendChild(strong);

    const tdActions = document.createElement('td');
    tdActions.className = 'user-actions';

    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn-small edit';
    btnEdit.textContent = '编辑';
    btnEdit.onclick = () => openEditModal(u);

    const btnDel = document.createElement('button');
    btnDel.className = 'btn-small del';
    btnDel.textContent = '删除';
    btnDel.onclick = () => openDeleteModal(u);

    tdActions.appendChild(btnEdit);
    tdActions.appendChild(btnDel);

    tr.appendChild(tdName);
    tr.appendChild(tdActions);

    // drag handlers
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

  if (!tbody.dataset.dragAttached) {
    tbody.dataset.dragAttached = '1';
    tbody.addEventListener('dragover', (e) => {
      e.preventDefault();
      const dragging = document.querySelector('.dragging');
      if (!dragging) return;
      const after = getDragAfterElement(tbody, e.clientY);
      if (after == null) tbody.appendChild(dragging);
      else tbody.insertBefore(dragging, after);
    });
  }
}

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
  $('#modal-form-links').value = '';
  $('#modal-form-status').innerText = '';
  $('#modal-form').dataset.mode = 'add';
  $('#modal-form-username').removeAttribute('disabled');
  $('#modal-form-title').innerText = '添加用户并编辑链接';
  showModal('modal-form');
}

async function openEditModal(username) {
  $('#modal-form-title').innerText = '编辑: ' + username;
  $('#modal-form').dataset.mode = 'edit';
  $('#modal-form').dataset.user = username;
  $('#modal-form-username').value = username;
  $('#modal-form-username').setAttribute('disabled', 'true');
  $('#modal-form-status').innerText = '';
  $('#modal-form-links').value = '';
  showModal('modal-form');

  const links = await api('/api/users/' + encodeURIComponent(username) + '/links');
  if (Array.isArray(links)) $('#modal-form-links').value = links.join('\n');
}

function closeAllModals() {
  // 不关闭登录框，除非已登录
  if (!$('#modal-login').classList.contains('hidden')) return;

  hideModal('modal-form');
  hideModal('modal-delete');
}

async function openDeleteModal(username) {
  $('#modal-delete-title').innerText = '删除: ' + username;
  $('#modal-delete-message').innerText = '将永久删除用户：' + username + '（无法撤销）';
  $('#modal-delete').dataset.user = username;
  $('#modal-delete-status').innerText = '';
  showModal('modal-delete');
}

document.addEventListener('DOMContentLoaded', () => {
  // 初始检查登录状态
  checkAuth();

  $('#login-form').addEventListener('submit', doLogin);
  $('#btn-logout').addEventListener('click', doLogout);

  $('#add-user').addEventListener('click', () => openAddModal());

  $('#modal-form-save').addEventListener('click', async () => {
    const mode = $('#modal-form').dataset.mode;
    const username = $('#modal-form-username').value.trim();
    const raw = $('#modal-form-links').value.trim();
    const arr = raw.split('\n').map(s => s.trim()).filter(Boolean);

    if (!username) { $('#modal-form-status').innerText = '用户名不能为空'; return; }

    if (mode === 'add') {
      const res = await api('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
      if (res && typeof res === 'string' && res.includes('exists')) {
        $('#modal-form-status').innerText = '用户已存在'; return;
      }
      if (!res) return; // auth failed

      if (arr.length > 0) {
        await api('/api/users/' + encodeURIComponent(username) + '/links', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ links: arr }) });
      }
      hideModal('modal-form');
      await renderUsers();
    } else if (mode === 'edit') {
      const orig = $('#modal-form').dataset.user;
      await api('/api/users/' + encodeURIComponent(orig) + '/links', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ links: arr }) });
      hideModal('modal-form');
      await renderUsers();
    }
  });

  $('#modal-form-copy').addEventListener('click', async () => {
    const mode = $('#modal-form').dataset.mode;
    let username;
    if (mode === 'add') username = $('#modal-form-username').value.trim();
    else username = $('#modal-form').dataset.user;

    if (!username) { $('#modal-form-status').innerText = '用户名不能为空，无法复制'; return; }

    let finalUrl = window.location.origin + '/' + encodeURIComponent(username);
    try {
      await navigator.clipboard.writeText(finalUrl);
      $('#modal-form-status').innerText = '已复制链接: ' + finalUrl;
      setTimeout(() => { $('#modal-form-status').innerText = ''; }, 1800);
    } catch (e) { $('#modal-form-status').innerText = '复制失败: ' + e; }
  });

  $('#modal-delete-cancel').addEventListener('click', () => hideModal('modal-delete'));
  $('#modal-delete-confirm').addEventListener('click', async () => {
    const user = $('#modal-delete').dataset.user;
    const res = await api('/api/users/' + encodeURIComponent(user), { method: 'DELETE' });
    if (res) { hideModal('modal-delete'); renderUsers(); }
  });

  $('#modal-form-cancel').addEventListener('click', () => hideModal('modal-form'));
  $('#modal-overlay').addEventListener('click', closeAllModals);

  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeAllModals();
  });
});