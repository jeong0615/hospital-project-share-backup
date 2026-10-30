// ── 세션 유틸 ──
function getUser() {
  const raw = sessionStorage.getItem('emr_user');
  if (!raw) { window.location.href = 'index.html'; return null; }
  return JSON.parse(raw);
}

function requireRole(...roles) {
  const u = getUser();
  if (!u) return null;
  if (!roles.includes(u.role)) {
    alert('접근 권한이 없습니다.');
    window.location.href = 'dashboard.html';
    return null;
  }
  return u;
}

function logout() {
  sessionStorage.removeItem('emr_user');
  window.location.href = 'index.html';
}

// ── 날짜 포맷 ──
function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('ko-KR', { year:'numeric', month:'2-digit', day:'2-digit' });
}
function fmtDateTime(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('ko-KR', { year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' });
}
function age(birth) {
  if (!birth) return '—';
  const b = new Date(birth), n = new Date();
  let a = n.getFullYear() - b.getFullYear();
  if (n < new Date(n.getFullYear(), b.getMonth(), b.getDate())) a--;
  return a + '세';
}

// ── 사이드바 렌더 ──
function renderSidebar(activePage) {
  const user = getUser();
  if (!user) return;

  const navItems = [
    { id:'dashboard', label:'대시보드', href:'dashboard.html', icon:'grid', roles:['DOC','PA','ADMIN'] },
    { id:'patients', label:'환자 목록', href:'patients.html', icon:'users', roles:['DOC','PA','ADMIN'] },
    { id:'patient-register', label:'환자 등록', href:'patient-register.html', icon:'user-plus', roles:['DOC','PA','ADMIN'] },
    { id:'access-logs', label:'접근 로그', href:'access-logs.html', icon:'shield', roles:['ADMIN'] },
  ];

  const icons = {
    grid: `<svg class="icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>`,
    users: `<svg class="icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
    'user-plus': `<svg class="icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>`,
    shield: `<svg class="icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  };

  const roleColor = { DOC:'badge-blue', PA:'badge-green', ADMIN:'badge-warn' };

  const html = `
  <div class="sidebar">
    <div class="sidebar-logo">
      <div class="mark">● HOSPITAL EMR</div>
      <div class="name">전자의무기록</div>
    </div>
    <div class="sidebar-section">메뉴</div>
    <nav class="sidebar-nav">
      ${navItems.filter(n => n.roles.includes(user.role)).map(n => `
        <a class="nav-item ${activePage === n.id ? 'active' : ''}" href="${n.href}">
          ${icons[n.icon]} ${n.label}
        </a>
      `).join('')}
    </nav>
    <div class="sidebar-footer">
      <div class="user-chip">
        <div class="user-avatar">${user.name.slice(0,2).toUpperCase()}</div>
        <div class="user-info">
          <div class="user-name">${user.name}</div>
          <div class="user-role">${user.role}</div>
        </div>
        <button onclick="logout()" title="로그아웃" style="background:none;border:none;cursor:pointer;color:var(--text-3);padding:4px;" >
          <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        </button>
      </div>
    </div>
  </div>`;

  document.getElementById('sidebar-mount').innerHTML = html;
}
