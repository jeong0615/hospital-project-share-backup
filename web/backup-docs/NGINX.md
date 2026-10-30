# Nginx

직접 읽은 `/etc/nginx/nginx.conf`는 `sites-enabled/*`, `conf.d/*.conf`, `modules-enabled/*.conf`, `mime.types`를 include합니다. symlink의 실제 파일 내용은 백업의 일반 파일로 보존했습니다. conf.d는 수집 시 파일이 없었습니다.

`active/sites-enabled/hospital`은 server_name `hospital-web.pp.ua`, listen 80, `/` → `IP_REDACTED:3000`, `/emr` → 301 `/emr/`, `/emr/` → `IP_REDACTED:5000/`입니다. trailing slash로 `/emr/` 접두부를 제거해 backend에 전달하는 설정입니다.

**주의: `hospital.bak_20260625_123126`도 sites-enabled/* 대상입니다.** 이름만 백업인 include 대상이며 단순 비활성으로 분류하지 않았습니다. 이 파일은 `server_name hospital- web.pp.ua` 및 EMR을 Node로 보내는 과거 값을 포함합니다. 현 프로세스가 메모리에 로드한 전체 설정은 확인할 수 없으며, 디스크 include 대상과 런타임 설정이 완전히 같다고 단정하지 않습니다. `inactive/default`는 sites-available에만 존재했습니다.

`nginx -T`는 비root 실행에서 로그/PID 접근 권한으로 완료되지 않았습니다. syntax is ok 메시지는 있었지만 전체 테스트 통과나 활성 덤프 확보를 뜻하지 않습니다. `sudo -n nginx -T`는 비밀번호 요구로 미확보입니다. 읽기 가능한 include 파일은 수집했습니다.

주 server에는 Host/Upgrade/Connection 전달이 있고 명시적인 X-Forwarded-For/X-Forwarded-Proto 설정은 없습니다. Cloudflare로부터 받은 헤더의 실제 신뢰 경계/secure 세션 동작은 별도 검증 대상입니다. 원본을 수정하지 않았습니다.

새 서버는 주 hospital 설정을 검토 후 사용하고 `.bak`를 활성 경로에 설치하지 않습니다. 모듈 include는 해당 Ubuntu 모듈 패키지가 있는 경우에만 사용합니다. 서비스 적용 전 새 서버에서 권한을 갖고 `nginx -t`로 검증합니다.
