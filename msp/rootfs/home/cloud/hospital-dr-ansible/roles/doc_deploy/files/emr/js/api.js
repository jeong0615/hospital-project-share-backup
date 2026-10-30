/**
 * js/api.js
 * 백엔드 API 호출을 위한 프론트엔드 공통 모듈
 */

const API_BASE_URL = window.location.pathname.startsWith('/emr') ? '/emr/api' : '/api'; // Node.js 백엔드 API 기본 경로

/**
 * 공통 fetch 래퍼 함수
 * @param {string} endpoint - API 엔드포인트 (예: '/Patients')
 * @param {object} options - fetch 옵션 (method, body 등)
 * @returns {Promise<any>} API 응답 데이터
 */
async function fetchApi(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;

    // 기본 헤더 설정 (JSON 통신)
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    try {
        const response = await fetch(url, { ...options, headers });
        const result = await response.json();

        // HTTP 상태 코드가 200번대가 아닐 경우 에러 발생
        if (!response.ok) {
            throw new Error(result.message || 'API 요청 처리 중 문제가 발생했습니다.');
        }

        return result;
    } catch (error) {
        console.error(`[API Error] ${endpoint}:`, error.message);
        throw error;
    }
}

// REST Method별 간편 호출 객체
const api = {
    get: (endpoint) => fetchApi(endpoint, { method: 'GET' }),

    post: (endpoint, data) => fetchApi(endpoint, {
        method: 'POST',
        body: JSON.stringify(data)
    }),

    patch: (endpoint, data) => fetchApi(endpoint, {
        method: 'PATCH',
        body: JSON.stringify(data)
    }),

    delete: (endpoint) => fetchApi(endpoint, {
        method: 'DELETE'
    })
};
