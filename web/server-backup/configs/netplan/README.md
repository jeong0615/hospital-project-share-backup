# Netplan — 사용자 제공본

`user-provided.yaml`은 사용자가 대화로 제공한 YAML을 그대로 저장한 자료입니다. 서버 파일을 직접 읽거나 원본과 바이트 단위로 대조한 결과는 아닙니다. 원본 파일명·조회 시각·이후 변경 여부는 독립 검증하지 않았습니다.

제공 내용: enp0s3, dhcp4=no, IP_REDACTED/24, default via IP_REDACTED, DNS IP_REDACTED 및 IP_REDACTED. 사용자 최종 Web IP/Gateway 기준과 일치합니다. 민감값은 발견되지 않았습니다. renderer는 명시되지 않았으며 추측하지 않습니다.

최초 자동 수집에서는 /etc/netplan/01-netcfg.yaml 읽기 권한이 거부되었습니다. 그 이력은 inventory에 보존합니다. 당시 실제 route는 임시 enp0s8 NAT 기본 경로였으므로 이 YAML과 런타임 상태는 구분합니다. 이 사용자 제공본에 enp0s8/wg0가 없다는 사실만으로 전체 네트워크 설정에 해당 인터페이스가 없다고 단정하지 않습니다.

운영 /etc/netplan은 변경하지 않았으며 netplan generate/try/apply도 실행하지 않았습니다.
