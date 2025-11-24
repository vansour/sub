const $ = sel => document.querySelector(sel);
const $all = sel => Array.from(document.querySelectorAll(sel));

const API_TOKEN = new URLSearchParams(window.location.search).get('api');

async function api(path, opts={}){
  // if the path is a relative API path, append api token as query param when available
  let url = path;
  try{
    const isAbsolute = /^https?:\/\//i.test(path);
    if (!isAbsolute && API_TOKEN) {
      url = path + (path.includes('?') ? '&' : '?') + 'api=' + encodeURIComponent(API_TOKEN);
    }
  }catch(e){ /* ignore */ }
  const res = await fetch(url, opts);
  const text = await res.text();
  try { return JSON.parse(text); } catch(e){ return text; }
}

async function renderUsers(){
  const list = await api('/api/users');
  const tbody = $('#user-list');
  tbody.innerHTML = '';
  if(!Array.isArray(list) || list.length===0){
    tbody.innerHTML = '<tr><td colspan="2" class="notice">没有用户 — 点击上方添加</td></tr>';
    return;
  }

  list.forEach(u => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${u}</strong></td>
      <td class="user-actions">
        <button class="btn-small edit">编辑</button>
        <button class="btn-small del">删除</button>
      </td>
    `;

    tr.querySelector('.edit').addEventListener('click', () => openEditModal(u));
    tr.querySelector('.del').addEventListener('click', () => openDeleteModal(u));

    tbody.appendChild(tr);
  });
}

// popups do the edit/add/delete, so keep editor hidden in main page

function showModal(id){
  $('#modal-overlay').classList.remove('hidden');
  $(`#${id}`).classList.remove('hidden');
}

function hideModal(id){
  $('#modal-overlay').classList.add('hidden');
  $(`#${id}`).classList.add('hidden');
}

function openAddModal(){
  $('#modal-form-username').value = '';
  $('#modal-form-links').value = '';
  $('#modal-form-status').innerText = '';
  $('#modal-form').dataset.mode = 'add';
  $('#modal-form-username').removeAttribute('disabled');
  // deletion handled separately via delete modal
  $('#modal-form-title').innerText = '添加用户并编辑链接';
  showModal('modal-form');
}

// note: saving handled by modal-form save handler

// removed showViewModal — viewing merged content no longer supported in UI

async function openEditModal(username){
  $('#modal-form-title').innerText = '编辑: ' + username;
  $('#modal-form').dataset.mode = 'edit';
  $('#modal-form').dataset.user = username;
  $('#modal-form-username').value = username;
  $('#modal-form-username').setAttribute('disabled', 'true');
  // deletion moved to separate delete confirmation modal
  $('#modal-form-status').innerText = '';
  $('#modal-form-links').value = '';
  showModal('modal-form');
  const links = await api('/api/users/' + encodeURIComponent(username) + '/links');
  if(Array.isArray(links)) $('#modal-form-links').value = links.join('\n');
}

function closeAllModals(){
  hideModal('modal-form'); hideModal('modal-delete');
}

async function openDeleteModal(username){
  $('#modal-delete-title').innerText = '删除: ' + username;
  $('#modal-delete-message').innerText = '将永久删除用户：' + username + '（无法撤销）';
  $('#modal-delete').dataset.user = username;
  $('#modal-delete-status').innerText = '';
  showModal('modal-delete');
}

document.addEventListener('DOMContentLoaded', () => {
  renderUsers();
  // open add user modal
  $('#add-user').addEventListener('click', () => openAddModal());
  // modal event bindings
  // modal-form save handler (add or edit)
  $('#modal-form-save').addEventListener('click', async () => {
    const mode = $('#modal-form').dataset.mode;
    const username = $('#modal-form-username').value.trim();
    const raw = $('#modal-form-links').value.trim();
    const arr = raw.split('\n').map(s => s.trim()).filter(Boolean);

    if (!username) { $('#modal-form-status').innerText = '用户名不能为空'; return; }

    if (mode === 'add') {
      // create user then set links
      const createUrl = '/api/users' + (API_TOKEN ? ('?api=' + encodeURIComponent(API_TOKEN)) : '');
      const res = await fetch(createUrl, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username})});
      if (!res.ok) { $('#modal-form-status').innerText = await res.text(); return; }
      if (arr.length > 0) {
        const putUrl = '/api/users/' + encodeURIComponent(username) + '/links' + (API_TOKEN ? ('?api=' + encodeURIComponent(API_TOKEN)) : '');
        await fetch(putUrl, {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({links: arr})});
      }
      hideModal('modal-form');
      await renderUsers();
    } else if (mode === 'edit') {
      const orig = $('#modal-form').dataset.user;
      const putUrl = '/api/users/' + encodeURIComponent(orig) + '/links' + (API_TOKEN ? ('?api=' + encodeURIComponent(API_TOKEN)) : '');
      const res = await fetch(putUrl, {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({links: arr})});
      if (!res.ok) { $('#modal-form-status').innerText = await res.text(); return; }
      hideModal('modal-form');
      await renderUsers();
    }
  });

  // copy final user link (the route /{username}) to clipboard
  $('#modal-form-copy').addEventListener('click', async () => {
    const mode = $('#modal-form').dataset.mode;
    let username;
    if (mode === 'add') username = $('#modal-form-username').value.trim();
    else username = $('#modal-form').dataset.user;
    if (!username) { $('#modal-form-status').innerText = '用户名不能为空，无法复制'; return; }
    let finalUrl = window.location.origin + '/' + encodeURIComponent(username);
    if (API_TOKEN) finalUrl += (finalUrl.includes('?') ? '&' : '?') + 'api=' + encodeURIComponent(API_TOKEN);
    try {
      await navigator.clipboard.writeText(finalUrl);
      $('#modal-form-status').innerText = '已复制链接: ' + finalUrl;
      setTimeout(() => { $('#modal-form-status').innerText = ''; }, 1800);
    } catch (e) { $('#modal-form-status').innerText = '复制失败: ' + e; }
  });

  $('#modal-delete-cancel').addEventListener('click', () => hideModal('modal-delete'));
  $('#modal-delete-confirm').addEventListener('click', async () => {
    const user = $('#modal-delete').dataset.user;
    const delUrl = '/api/users/' + encodeURIComponent(user) + (API_TOKEN ? ('?api=' + encodeURIComponent(API_TOKEN)) : '');
    const res = await fetch(delUrl, {method:'DELETE'});
    if (res.ok) { hideModal('modal-delete'); renderUsers(); } else { $('#modal-delete-status').innerText = await res.text(); }
  });

  // modal form cancel/close
  $('#modal-form-cancel').addEventListener('click', () => hideModal('modal-form'));
  // view modal removed — no extra handlers

  // overlay click closes modals
  $('#modal-overlay').addEventListener('click', closeAllModals);

  // Esc key closes any open modal
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeAllModals();
  });
});
