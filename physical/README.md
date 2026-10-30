# Physical Network

이 디렉터리는 Hospital DR 프로젝트에서 사용한 실제 네트워크 장비의 구성 정보, 설정 명령어, 확인 명령어 및 실행 결과를 보관한다.

실장비 설정을 GitHub Repository만 보고도 다시 확인하거나 재구성할 수 있도록 장비별 설정과 검증 결과를 문서화한다. 이 디렉터리의 파일은 실제 장비에 자동으로 설정을 적용하지 않으며, 장비 설정 변경이나 초기화도 수행하지 않는다.

<br>

## 구조

```text
physical/
├── router/
│   └── R1.md
├── access-switch/
│   └── L2-SW1.md
├── core-switch/
│   ├── Active-L3-SW.md
│   └── Standby-L3-SW.md
└── README.md
```
`configs/`에는 장비별 주요 설정 명령어 및 필요한 경우 `show running-config` 기반의 설정 내용을 보관한다.

`docs/`에는 실제 네트워크 토폴로지, IP 주소 체계, 장비 연결 관계 및 통신 검증 결과를 기록한다.

<br>

## 포함 대상

Physical Network 백업에는 다음 내용을 포함한다.

- 실제 Router 설정
- 실제 Switch 설정
- Interface IP 및 Port 정보
- VLAN 구성
- Trunk / Access Port 설정
- Routing 설정
- OSPF 등 Dynamic Routing 설정
- 장비 관리 접속 설정
- 실제 장비 연결 관계
- Ping / Traceroute 결과
- Routing Table 확인 결과
- VLAN / Trunk 상태 확인 결과
- 장애 및 정상 통신 검증 결과

설정에 사용한 명령어뿐 아니라 실제 장비에서 확인한 결과도 함께 기록한다.

<br>

## 장비별 문서 작성 방식

각 장비 문서는 다음 형식을 기준으로 작성한다.

```text
장비 역할
→ Interface / IP 정보
→ 주요 설정 명령어
→ 확인 명령어
→ 실제 실행 결과
→ 검증 결과
```

예시:

```cisco
show ip interface brief
show ip route
show vlan brief
show interfaces trunk
show running-config
```

실제 장비에서 지원하지 않는 명령어는 기록하지 않으며, 장비 모델과 IOS 기능에 맞는 명령어를 사용한다.

<br>

## 관리 접속

프로젝트에서 사용하는 실제 장비 중 일부는 SSH/crypto 기능을 지원하지 않으므로 관리 접속 방식은 실제 장비 환경에 맞춰 기록한다.

관리 접속 설정을 기록할 때에는 다음 내용을 확인한다.

- Console / Telnet / SSH 사용 여부
- VTY 설정
- Local User 사용 여부
- Enable 설정
- Management IP
- 관리 접근 가능 네트워크

비밀번호 또는 credential 원문은 GitHub 문서에 직접 기록하지 않는 것을 원칙으로 한다.

<br>

## 재구성 순서

실제 네트워크 장비를 다시 구성할 경우 다음 순서를 기준으로 한다.

1. 실제 장비 모델 및 Interface 구성을 확인한다.
2. 장비 간 물리적 Cable 연결 상태를 확인한다.
3. Hostname 및 기본 관리 설정을 구성한다.
4. Interface 상태와 IP 주소를 설정한다.
5. VLAN 및 Access/Trunk Port를 구성한다.
6. Routing 및 필요한 Dynamic Routing을 구성한다.
7. Gateway 및 외부망 연결을 확인한다.
8. 관리 접속 설정을 구성한다.
9. 각 장비에서 Interface, VLAN, Routing 상태를 확인한다.
10. End-to-End Ping 및 필요한 서비스 통신을 검증한다.

설정을 적용하기 전에 현재 `running-config`와 기존 네트워크 상태를 먼저 확인한다.

<br>

## 검증 항목

실장비 구성 완료 후 최소 다음 항목을 확인한다.

```text
Interface Up/Up 여부
VLAN 정상 생성 여부
Access / Trunk Port 상태
Routing Table
OSPF Neighbor 상태
Gateway 통신
장비 간 Ping
GNS3 네트워크와의 연결
서버 네트워크 통신
외부망 통신
```

각 검증 결과는 명령어와 실제 출력 결과를 함께 기록한다.

<br>

## Git 제외 및 별도 관리 항목

다음 정보는 Repository에 그대로 저장하지 않는다.

- 실제 운영 비밀번호
- Enable Secret CREDENTIAL_REDACTED
- SSH Private Key
- SNMP Community String
- VPN Private Key
- 인증서 Private Key
- 외부 서비스 Credential
- 기타 인증 및 Secret 정보

필요한 경우 설정 파일에서는 placeholder 형태로 변경한다.

```text
<REDACTED>
<SECRET>
<MANAGEMENT_PASSWORD>
```

<br>

## 안전 원칙

- 문서화 과정에서 실제 장비의 설정을 임의로 변경하지 않는다.
- `write erase`, `erase startup-config`, `reload` 등 초기화 명령어는 백업 과정에서 실행하지 않는다.
- 기존 `running-config`를 확인한 후 필요한 설정만 적용한다.
- 실제 장비와 GNS3 설정은 서로 다른 디렉터리에서 관리한다.
- 설정 변경 전후의 통신 상태를 확인한다.
- GitHub에 업로드하기 전에 credential 및 민감정보 포함 여부를 확인한다.
