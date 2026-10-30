/**
 * js/auth.js
 * 로그인, 세션 관리 및 권한 체크 로직
 */

// 전역 스코프에서 selectedRole 변수 관리 (index.html의 탭 선택과 연동)
let selectedRole = 'DOC';

/**
 * 역할(Role) 선택 탭 클릭 시 호출
 * @param {HTMLElement} el - 클릭된 버튼 엘리먼트
 * @param {string} role - 선택된 역할 ('DOC', 'PA', 'ADMIN')
 */
function selectRole(el, role) {
    document.querySelectorAll('.role-tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    selectedRole = role;
}

/**
 * 로그인 폼 제출 시 호출 (API 연동)
 * @param {Event} e - submit 이벤트 객체
 */
async function handleLogin(e) {
    e.preventDefault();
    const idInput = document.getElementById('loginId');
    const pwInput = document.getElementById('loginPw');
    const err = document.getElementById('errMsg');

    const login_id = idInput.value.trim();
    const password = pwInput.value;

    if (!login_id || !password) {
        err.textContent = '아이디와 비밀번호를 모두 입력해주세요.';
        err.classList.add('show');
        return;
    }

    try {
        // 백엔드 로그인 API 호출 (js/api.js의 api 객체 사용)
        const response = await api.post('/auth/login', { login_id, password });

        if (response.success) {
            // API 응답 데이터(user_id, login_id, name, role)를 세션 스토리지에 저장
            // 프론트엔드에서 선택한 역할(selectedRole)과 실제 DB 역할의 검증은 백엔드에서 하거나
            // 반환된 데이터의 role을 우선적으로 사용할 수 있습니다. 여기서는 DB의 역할을 신뢰합니다.
            sessionStorage.setItem('emr_user', JSON.stringify(response.data));

            err.classList.remove('show');

            // 로그인 성공 시 대시보드로 이동
            window.location.href = 'dashboard.html';
        }
    } catch (error) {
        // API 요청 실패 또는 401/400 에러 처리
        err.textContent = error.message || '아이디 또는 비밀번호를 확인해주세요.';
        err.classList.add('show');
    }
}