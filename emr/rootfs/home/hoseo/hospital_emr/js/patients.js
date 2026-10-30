/**
 * js/Patients.js
 * 프론트엔드 환자 데이터 처리 로직 (백엔드 API 연동)
 */

// 1. 환자 목록 불러오기 (검색어, 성별 필터 포함)
async function fetchPatientsList(searchQuery = '', genderFilter = '') {
    try {
        let url = '/Patients';
        const params = new URLSearchParams();

        if (searchQuery) params.append('search', searchQuery);
        if (genderFilter) params.append('gender', genderFilter);

        if (params.toString()) {
            url += `?${params.toString()}`;
        }

        const response = await api.get(url);
        return response.success ? response.data : [];
    } catch (error) {
        console.error('환자 목록 불러오기 실패:', error);
        return [];
    }
}

// 2. 환자 상세 정보 불러오기
async function fetchPatientDetail(patientId) {
    try {
        const response = await api.get(`/Patients/${patientId}`);
        return response.success ? response.data : null;
    } catch (error) {
        console.error('환자 상세 정보 불러오기 실패:', error);
        return null;
    }
}

// 3. 환자 신규 등록
async function registerPatient(patientData) {
    try {
        const response = await api.post('/Patients', patientData);

        // 등록 성공 시 프론트엔드 접근 로그 기록 (ADMIN 추적용)
        const user = getUser();
        if (user) {
            await api.post('/logs', { user_id: user.user_id, action_type: 'CREATE_PATIENT' });
        }

        return response;
    } catch (error) {
        console.error('환자 등록 실패:', error);
        throw error;
    }
}

// 4. 환자 정보 수정
async function updatePatient(patientId, updateData) {
    try {
        const response = await api.patch(`/Patients/${patientId}`, updateData);

        // 수정 성공 시 프론트엔드 접근 로그 기록
        const user = getUser();
        if (user) {
            await api.post('/logs', { user_id: user.user_id, action_type: 'EDIT_PATIENT' });
        }

        return response;
    } catch (error) {
        console.error('환자 정보 수정 실패:', error);
        throw error;
    }
}