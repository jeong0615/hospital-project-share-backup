# [ROADMAP] 개발 단계

<br>

| 구분 | 담당 영역 | 주요 역할 |
| :--- | :--- | :--- |
| **정승철** | MSP / CSP / IaC / Monitoring / AWS DR | AWS DR 환경 구축, IaC 자동화, 모니터링, DB 하이브리드 복제 |
| **이재훈** | Web / DNS / Physical / Security / HSRP | Web 서버 구축, 실제 장비 구성 및 활성화, 코어·게이트웨이 이중화 |
| **윤종민** | EMR / DB / GNS3 / Firewall / CARP | EMR·DB 서버 구축, GNS3 내부망 토폴로지 설계, 방화벽 이중화 |

<br>
<br>
<br>
<br>

# [On-Premise]
>## [HIS] 병원 서버 및 GNS3
>| 단계 | 항목 | 목표 | 수행 방법 | 진행률 |
>| :--- | :--- | :--- | :--- | :--- |
>| **[H1]** | **병원 서버 구축** | 서비스 인프라 마련 | Ubuntu 22.04 기반 Web, Doc, DB 서버 구축 및 패키지 구성 | **100%** <br> &nbsp; |
>| **[H2]** | **GNS3 네트워크 구성** | 내부 HIS 네트워크 구축 | GNS3 L2/L3 노드 구성 및 내부 네트워크 통신 확인 | **100%** <br> &nbsp; |
>| **[H3]** | **외부 네트워크 연동** | GNS3 외부 통신 경로 확보 | GNS3 Host를 실제 L2 Switch에 연결하고 Router를 통한 외부 통신 확인 | **100%** <br> &nbsp; |
>| **[H4]** | **내부망 세분화** | PC·서버 네트워크 분리 | GNS3에서 VLAN 10(PC), VLAN 30(Doc/DB) 구성 및 통신 검증 | **100%** <br> &nbsp; |
>| **[H5]** | **동적 라우팅** | GNS3 내부 경로 구성 | OSPF 프로세스 구성 및 동적 라우팅 경로 검증 | **100%** <br> &nbsp; |
>| **[H6]** | **GNS3 네트워크 HA** | 내부 Gateway/Core 가용성 확보 | VLAN 10·30 VIP 기반 Gateway 이중화 및 네트워크 장애 전환 검증 | **100%** <br> &nbsp; |
>| **[H7]** | **이중화 방화벽** | 방화벽 가용성 확보 | pfSense VIP 구성 및 CARP 프로토콜 적용 | **100%** <br> &nbsp; |
>| **[H8]** | **경계 보안** | 외부·내부 네트워크 보호 | pfSense WAN/LAN/DMZ 구성 및 방화벽 정책 적용 | **100%** <br> &nbsp; |
>| **[H9]** | **네트워크 접근통제** | 불필요한 통신 차단 | ACL 및 Firewall 정책으로 허용된 서비스·포트만 통신 허용 | **100%** <br> &nbsp; |
>| **[H10]** | **도메인 주소** | 외부 Web 서비스 연결 | Cloudflare DNS 및 SSL/TLS 적용 | **100%** <br> &nbsp; |
>| **[H11]** | **웹서버 보안** | Web 서비스 보호 | Cloudflare WAF 및 Application WAF 이중 적용 | **100%** <br> &nbsp; |
>| **[H12]** | **Doc/EMR 접근 제어** | 외부 직접 접근 차단 | /emr 외부 접근 제한 및 접근 정책 적용 | **100%** <br> &nbsp; |
>| **[H13]** | **보안 기능 확장** | 침입 탐지·방지 | pfSense IDS/IPS 적용 및 이벤트 탐지 검증 | **100%** <br> &nbsp; |

>## [Physical] 실제 장비
>| 단계 | 항목 | 목표 | 수행 방법 | 진행률 |
>| :--- | :--- | :--- | :--- | :--- |
>| **[P1]** | **L2/L3 장비 기본 설정** | 실제 장비 초기 구성 | Hostname, telnet, Enable Secret, 관리 IP 등 기본 설정 | **100%** <br> &nbsp; |
>| **[P2]** | **L3 코어 및 VLAN 구성** | Web 및 Uplink 네트워크 구성 | L3-SW1/SW2 코어 구성, VLAN 20(Web) 및 VLAN 100(Uplink) SVI 구성 | **100%** <br> &nbsp; |
>| **[P3]** | **Trunk / Access 구성** | 실제 네트워크 연결 | L2 ↔ L3 Uplink 및 Web Server·GNS3 Host 연결 포트 구성 | **100%** <br> &nbsp; |
>| **[P4]** | **HSRP 구성** | Web Gateway 이중화 | L3-SW1/SW2에서 VLAN 20 HSRP Virtual IP 구성 및 장애 전환 확인 | **100%** <br> &nbsp; |
>| **[P5]** | **L3 Routing 구성** | Web 및 외부 통신 경로 확보 | VLAN 20 ↔ Core/Uplink 구간 L3 라우팅 및 기본 경로 구성 | **100%** <br> &nbsp; |
>| **[P6]** | **RIPv2 구성** | 실제 장비 동적 라우팅 | L3 Core ↔ Router 간 RIPv2 구성 및 경로 정보 교환 확인 | **100%** <br> &nbsp; |
>| **[P7]** | **RSTP 구성** | 실제 스위치 루프 방지 | L2 Switch 및 L3 Switch의 L2 구간 RSTP 설정 | **100%** <br> &nbsp; |
>| **[P8]** | **ACL 적용** | 실제 네트워크 접근 제어 | Web·관리·Uplink 구간의 불필요한 통신 차단 및 허용 서비스 지정 | **100%** <br> &nbsp; |

<br>
<br>
<br>
<br>

# [Cloud]

>## [MSP] 외부 통합 관제 서버
>| 단계 | 항목 | 목표 | 수행 방법 | 진행률 |
>| :--- | :--- | :--- | :--- | :--- |
>| **[M1]** | **MSP 통합 관제 서버** | 중앙 관제 및 DR 제어 거점 구축 | pfSense 격리 환경에서 Ubuntu 22.04 기반 MSP 서버 및 관리 서비스 구성 | **100%** <br> &nbsp; |
>| **[M2]** | **On-Prem ↔ MSP VPN** | 안전한 관제 통신 경로 확보 | WireGuard 기반 On-Premise ↔ MSP 전용 VPN 구성 및 통신 검증 | **100%** <br> &nbsp; |
>| **[M3]** | **Zabbix 관제 플랫폼** | 인프라 및 DR 상태 수집 | Zabbix Server/Agent/SNMP 기반 서버·네트워크 상태 및 DR 자동화 Item 수집, Problem/Recovery 연계 | **100%** <br> &nbsp; |
>| **[M4]** | **Grafana 통합 대시보드** | 인프라·DR·보안 상태 시각화 | Zabbix API 및 Wazuh OpenSearch Indexer를 Grafana와 연동 | **100%** <br> &nbsp; |
>| **[M5]** | **Wazuh SIEM 플랫폼** | 중앙 보안 로그 분석 환경 구축 | Wazuh Manager, Indexer, Dashboard 구성 및 Grafana Read-Only 연동 | **100%** <br> &nbsp; |
>| **[M6]** | **Terraform / Ansible 관리 환경** | AWS DR 중앙 제어 | MSP에서 Terraform 기반 프로비저닝 및 Ansible 기반 구성·복구 자동화 | **100%** <br> &nbsp; |
>| **[M7]** | **Slack 장애 알림** | 장애 상황 실시간 전달 | 실제 Zabbix Problem/Recovery Event → ChatOps → Slack 자동 알림 연계 | **100%** <br> &nbsp; |
>| **[M8]** | **DR 2인 승인 ChatOps** | 관리자 이중 승인 통제 | Slack Failover·Failback·Emergency 3-App 기반 2인 승인, Global Lock, Audit, Health/Security Gate 및 ngrok HTTPS Endpoint 연동 | **100%** <br> &nbsp; |
>| **[M9]** | **암호화 DB 백업 수집** | 별도 복구 데이터 확보 | On-Prem에서 생성한 `.sql.gz.enc` 및 `.master_status`를 MSP로 전송·관리 | **100%** <br> &nbsp; |
>| **[M10]** | **RTO/RPO 관제** | DR 성능 정량 측정 | Zabbix·Grafana 및 Evidence Collector로 실제 Live E2E RTO/RPO 기록·증적화 | **100%** <br> &nbsp; |
>| **[M11]** | **Cloudflare Secret 관리** | DNS 자동화 인증정보 보호 | Cloudflare API Token을 AWS SSM SecureString에서 런타임 조회하도록 통일 | **100%** <br> &nbsp; |
>| **[M12]** | **DR 실행 안정성 / 상태 관리** | 페일오버/페일백 안정성 확보 | Persistent DR State, 실행 Lock, Timeout·Stale 복구, DNS Snapshot/Rollback, Partial Failure 처리 | **100%** <br> &nbsp; |
>| **[M13]** | **네트워크 DR Health 게이트** | 안전한 Failback | SNMP/Zabbix 기반 Network Health를 검증하고 Web/EMR/DB/Network 300초 정상 시 Failback 요청 생성 | **100%** <br> &nbsp; |

>## [CSP] AWS DR 서버
>| 단계 | 항목 | 목표 | 수행 방법 | 진행률 |
>| :--- | :--- | :--- | :--- | :--- |
>| **[A1]** | **AWS VPC 인프라** | DR 클라우드 거점 구축 | Terraform 기반 VPC, Subnet, IGW, Route Table 구성 | **100%** <br> &nbsp; |
>| **[A2]** | **Public / Private Subnet 분리** | DR 서버 보안 영역 분리 | Web은 Public, Doc/EMR·DB는 Private Subnet에 배치 | **100%** <br> &nbsp; |
>| **[A3]** | **Security Group** | 서비스별 네트워크 접근 통제 | Web/Doc/DB별 최소 포트 기반 SG 구성 및 보안 정책 정비 | **100%** <br> &nbsp; |
>| **[A4]** | **Web NAT Instance** | Private 서버 외부 통신 | AWS Web EC2를 NAT Instance로 사용하고 Private Subnet Route를 Web ENI로 구성 | **100%** <br> &nbsp; |
>| **[A5]** | **DR EC2 프로비저닝** | Web/Doc/DB DR 인프라 자동 생성 | Terraform으로 Web, Doc/EMR, DB EC2 생성 | **100%** <br> &nbsp; |
>| **[A6]** | **DR 서버 구성 자동화** | 서버 환경 표준화 | Ansible 기반 Web, Doc/EMR, DB 구성 및 Existing-host 재프로비저닝 E2E | **100%** <br> &nbsp; |
>| **[A7]** | **IAM / SSM 최소권한 구조** | AWS 접근 및 Secret 통제 | IAM 권한 분리, GitHub OIDC, SSM SecureString 및 최소권한 정책 관리 | **100%** <br> &nbsp; |
>| **[A8]** | **DR 서비스 Docker화** | 서비스 실행환경 표준화 | Web/EMR Docker Image 구성, Health Check 및 보안 Hardening | **100%** <br> &nbsp; |
>| **[A9]** | **ECR 이미지 관리** | 검증된 DR 이미지 보관 | Private ECR, Immutable SHA Tag, 보안 Scan 및 검증 이미지 배포 | **100%** <br> &nbsp; |
>| **[A10]** | **GitHub Actions / OIDC** | 안전한 CI/CD 구축 | Build → Trivy → Health → Security Gate → OIDC ECR Push | **100%** <br> &nbsp; |
>| **[A11]** | **AWS S3 원격지 백업** | 오프사이트 DB 백업 확보 | MSP 암호화 Dump를 S3에 업로드하고 Versioning/Lifecycle/SSE 적용 | **100%** <br> &nbsp; |
>| **[A12]** | **DB Dump 복구 자동화** | NR 장애 시 보조 복구 | 암호화 Dump·master_status·File/Position·Checksum 검증 및 복구 Workflow 구성 | **100%** <br> &nbsp; |
>| **[A13]** | **On-Prem → AWS CDC(NR)** | 데이터 손실 최소화 | MySQL Binlog/Position 기반 On-Prem DB → AWS DR DB Native Replication | **100%** <br> &nbsp; |
>| **[A14]** | **DR 생명주기 / FinOps** | DR 운영비 최소화 | EC2 Stop/Start, Web NAT Instance Route, EIP·ENI 유지 및 비용 최적화 | **100%** <br> &nbsp; |
>| **[A15]** | **Cloudflare DNS / TLS DR 전환** | Web 서비스의 안전한 DR 전환 | Origin CA + Full(strict), DNS Snapshot 기반 CNAME ↔ AWS A 전환·복원 및 External E2E 검증 | **100%** <br> &nbsp; |
>| **[A16]** | **AWS Cloud Security / XDR 연계** | AWS DR 보안 이벤트 중앙 관제 | CloudTrail Event History → Collector → Wazuh Indexer → Grafana/XDR 연계 및 실제 이벤트 수집 검증 | **100%** <br> &nbsp; |
>| **[A17]** | **AWS DR 전용 WireGuard** | DB 복제 전용 VPN | `wg-aws-dr` (`10.251.0.0/24`, UDP 51821) 기반 On-Prem DB ↔ AWS DR 복제 경로 구성 | **100%** <br> &nbsp; |

<br>
<br>
<br>
<br>

# [Hybrid]
>| 단계 | 항목 | 테스트 / 검증 내용 | 성공 여부 |
>| :--- | :--- | :--- | :--- |
>| **[T1]** | **네트워크 기본 통신** | GNS3 VLAN 10/30 내부 통신, Physical VLAN 20 Web 통신, GNS3 ↔ 실제 네트워크 및 외부 서비스 접근 경로 확인 | **[✓]** <br> &nbsp; |
>| **[T2]** | **On-Premise HA 검증** | GNS3 Gateway HA·OSPF 경로 변경, Physical HSRP·RSTP·RIPv2 장애 전환, pfSense CARP Firewall Failover 확인 | **[✓]** <br> &nbsp; |
>| **[T3]** | **네트워크 보안 검증** | VLAN/ACL 접근 제어, pfSense Firewall, IDS/IPS 허용·차단 정책 검증 | **[✓]** <br> &nbsp; |
>| **[T4]** | **Web 보안 검증** | Cloudflare/Application WAF의 XSS·SQLi 차단, HTTPS/SSL 및 접근 정책 확인 | **[✓]** <br> &nbsp; |
>| **[T5]** | **Hybrid 네트워크 연동** | On-Prem ↔ MSP WireGuard 통신, MSP ↔ AWS 관리 경로 및 DB 복제 통신 경로 확인 | **[✓]** <br> &nbsp; |
>| **[T6]** | **DB 백업 / 복구 검증** | On-Prem 암호화 Dump → MSP → S3 전송 및 Dump 기반 DB 복구·정합성 확인 | **[✓]** <br> &nbsp; |
>| **[T7]** | **DB 실시간 NR 검증** | Position 기반 On-Prem DB → AWS DR DB 실시간 복제 및 데이터 정합성 확인 | **[✓]** <br> &nbsp; |
>| **[T8]** | **통합 관제 검증** | Zabbix 서버·네트워크 장애 감지, Grafana RTO/RPO 지표 시각화 및 장애 식별 확인 | **[✓]** <br> &nbsp; |
>| **[T9]** | **통합 보안 관제 검증** | Wazuh Agent → MSP SIEM 이벤트 수집, 보안 이벤트 탐지 및 Slack 알림 확인 | **[✓]** <br> &nbsp; |
>| **[T10]** | **ChatOps / DR 승인 검증** | 장애 이벤트 → Slack 알림 → 관리자 2인 승인 → 중복 실행 방지 및 자동화 실행 확인 | **[✓]** <br> &nbsp; |
>| **[T11]** | **Failover / DR 서비스 검증** | 장애 감지 → 승인 → Terraform/Ansible → AWS DR 활성화 → DNS 전환 → Web/EMR/DB Health Check | **[✓]** <br> &nbsp; |
>| **[T12]** | **Failback / RTO·RPO 검증** | AWS DB Export → On-Prem Import, Doc Sync, DNS 원복 및 Failover/Failback 시간·RPO 측정 | **[✓]** <br> &nbsp; |
>| **[T13]** | **End-to-End DR 검증** | On-Prem 장애 → AWS Failover → DR 데이터 생성 → Failback → On-Prem 데이터 복귀 전체 시나리오 검증 | **[✓]** <br> &nbsp; |
>| **[T14]** | **유지보수** | Web, EMR, DB, MSP 실제 스트립트 경로 및 PHYSICAL, GNS3 설정 명령어 GitHub 백업 | **[✓]** <br> &nbsp; |
