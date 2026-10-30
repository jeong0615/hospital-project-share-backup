/**
 * js/medical-records.js
 * 프론트엔드 진료 기록 데이터 처리 로직 (백엔드 API 연동)
 */

// 1. 특정 환자의 진료 기록 목록 불러오기
async function fetchMedicalRecords(patientId) {
    try {
        const response = await api.get(`/medical-records/patient/${patientId}`);
        return response.success ? response.data : [];
    } catch (error) {
        console.error('진료 기록 불러오기 실패:', error);
        return [];
    }
}

// 2. 새로운 진료 기록 추가
async function addMedicalRecord(recordData) {
    try {
        const response = await api.post('/medical-records', recordData);

        // 진료 기록 추가 성공 시 접근 로그 기록 (보안 감사용)
        const user = getUser();
        if (user) {
            await api.post('/logs', { user_id: user.user_id, action_type: 'CREATE_RECORD' });
        }

        return response;
    } catch (error) {
        console.error('진료 기록 추가 실패:', error);
        throw error;
    }
}

// 3. 대시보드용 최근 진료 기록 불러오기
async function fetchRecentRecords() {
    try {
        const response = await api.get('/medical-records/recent');
        return response.success ? response.data : [];
    } catch (error) {
        console.error('최근 진료 기록 불러오기 실패:', error);
        return [];
    }
}

// 4. 대시보드 통계 데이터 (오늘 외래, 이번 달 진료 등) 불러오기
async function fetchDashboardStats() {
    try {
        const response = await api.get('/medical-records/stats');
        return response.success ? response.data : null;
    } catch (error) {
        console.error('대시보드 통계 데이터 불러오기 실패:', error);
        return null;
    }
}