# 스크립트 범위

모두 이번 운영 서버에서 실행하지 않았으며 bash -n 구문 검사만 수행합니다. 새 대상에서 deploy-web.sh로 소스를 준비하고 WEB_SETUP을 따릅니다. 의존성은 운영자가 새 대상에서 npm ci로 설치합니다. install-dependencies 자동 설치 스크립트는 제공하지 않으며 check-prerequisites.sh로 존재 여부만 확인합니다. health/verify는 읽기 요청입니다.
