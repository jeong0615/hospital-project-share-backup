from flask import Flask, render_template, jsonify
import os
import mysql.connector
from mysql.connector import Error
from datetime import datetime, date

app = Flask(__name__)

# [설정] DB 연결 정보
db_config = {
    'host': 'IP_REDACTED', # 실제 환경에 맞게 수정
    'user': 'admin',
    'password': os.getenv('DB_PASSWORD'),
    'database': 'hospital_db',
    'auth_plugin': 'mysql_native_password' # 연결 오류 방지용 추가
}

# 1. 메인 페이지: 환자 전체 목록 조회
@app.route('/')
def index():
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # 수정된 SQL: 진료 기록이 없는 환자도 표시되도록 LEFT JOIN을 유지하며 잘린 쿼리 완성
        query = """
            SELECT p.patient_id, p.name, p.birth_date, p.gender,
                   MAX(d.name) as doctor_name
            FROM Patients p
            LEFT JOIN MedicalRecords m ON p.patient_id = m.patient_id
            LEFT JOIN Doctors d ON m.doctor_id = d.doctor_id
            GROUP BY p.patient_id, p.name, p.birth_date, p.gender
            ORDER BY p.patient_id ASC
        """
        cursor.execute(query)
        patients = cursor.fetchall()

        # 날짜 객체를 템플릿에서 쓰기 편하게 문자열로 변환 (선택 사항)
        for p in patients:
            if isinstance(p['birth_date'], (date, datetime)):
                p['birth_date'] = p['birth_date'].strftime('%Y-%m-%d')

        return render_template('index.html', patients=patients)

    except Error as e:
        return f"데이터베이스 연결 실패: {str(e)}"

    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# 2. 상세 조회 API: 특정 환자를 클릭했을 때 실행
@app.route('/patient_details/<int:id>')
def patient_details(id):
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # 수정된 SQL: 의사가 퇴사(NULL)했더라도 환자 이름과 진료 기록은 나오도록 LEFT JOIN 처리
        query = """
            SELECT p.name as patient_name,
                   IFNULL(d.name, '담당의 없음') as doctor_name,
                   IFNULL(d.department, '-') as department,
                   m.visit_date, m.diagnosis
            FROM MedicalRecords m
            JOIN Patients p ON m.patient_id = p.patient_id
            LEFT JOIN Doctors d ON m.doctor_id = d.doctor_id
            WHERE p.patient_id = %s
            ORDER BY m.visit_date DESC LIMIT 1
        """
        cursor.execute(query, (id,))
        details = cursor.fetchone()

        if details:
            # datetime 및 date 객체 JSON 변환 처리
            for key, value in details.items():
                if isinstance(value, (datetime, date)):
                    details[key] = value.strftime('%Y-%m-%d %H:%M:%S')
            return jsonify(details)
        else:
            return jsonify({"error": "진료 기록이 없습니다."}), 404

    except Error as e:
        return jsonify({"error": f"DB 오류: {str(e)}"}), 500

    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == '__main__':
    app.run(host='IP_REDACTED', port=5000, debug=True)
