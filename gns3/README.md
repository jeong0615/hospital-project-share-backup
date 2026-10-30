# GNS3 Network

이 디렉터리는 Hospital DR 프로젝트의 GNS3 기반 병원 내부 네트워크를 다시 구성할 수 있도록 네트워크 토폴로지, 장비별 설정, IP/VLAN 정보 및 검증 결과를 보관한다.

GNS3 Project 자체에만 의존하지 않고 Repository의 문서와 설정 내용을 통해 주요 네트워크 구성을 확인하고 재구성할 수 있도록 관리한다.

이 디렉터리의 파일은 GNS3 장비 설정을 자동으로 실행하거나 실제 네트워크 환경을 변경하지 않는다.

<br>

## 구조

```text
gns3/
├── core-switch/
│   ├── ESW1.md
│   └── ESW2.md
└── README.md
```

<br>

## 네트워크 구성

GNS3 환경은 병원 내부 네트워크를 구성하며 Firewall, Core Switch, Access Switch 및 서버/클라이언트로 구성한다.

현재 주요 네트워크는 다음과 같다.

| 구분 | 네트워크 / IP | 역할 |
|---|---|---|
| WAN | `IP_REDACTED/24` | 외부망 연결 |
| WAN VIP | `IP_REDACTED` | Firewall WAN HA |
| Firewall LAN | `IP_REDACTED/24` | Firewall ↔ Core |
| LAN VIP | `IP_REDACTED` | Firewall LAN HA |
| VLAN 10 | `IP_REDACTED/24` | 사용자 네트워크 |
| VLAN 30 | `IP_REDACTED/24` | 서버 네트워크 |
| DB | `IP_REDACTED` | DB Server |
| EMR | `IP_REDACTED` | EMR Server |

세부 Interface IP와 Port 연결 관계는 별도 문서에서 관리한다.

<br>

## 주요 장비

### Firewall

- pf1
- pf2

Firewall 문서에는 다음 내용을 기록한다.

- WAN / LAN Interface
- WAN VIP / LAN VIP
- Firewall Rule
- NAT
- Default Route
- HA 구성
- Failover 확인 결과

<br>

### Core Switch

- ESW1
- ESW2

Core Switch 문서에는 다음 내용을 기록한다.

- Interface 구성
- VLAN 10 / VLAN 30
- SVI
- VLAN Gateway
- Trunk
- Routing
- OSPF
- Core Switch 간 연결
- Routing 및 Neighbor 확인 결과

<br>

### Access Switch

- Switch1
- Switch2
- Switch3

Access Switch 문서에는 다음 내용을 기록한다.

- Access Port
- Trunk Port
- VLAN 할당
- 연결 Host
- Uplink 연결
- VLAN / Trunk 확인 결과

별도 설정이 거의 없는 L2 Switch는 연결 관계와 필요한 설정만 기록한다.

<br>

### Host

주요 Host의 다음 정보를 기록한다.

- IP Address
- Subnet Mask
- Default Gateway
- VLAN
- 연결 Switch / Port
- DHCP 또는 Static 여부
- Ping 결과

<br>

## 장비별 설정 기록

GNS3 장비의 모든 CLI 입력을 단순 저장하는 것이 아니라 네트워크를 다시 구성하는 데 필요한 핵심 설정을 기록한다.

주요 기록 대상은 다음과 같다.

```text
Interface
IP Address
VLAN
Access / Trunk
SVI
Routing
OSPF
Gateway
Firewall Rule
NAT
HA
```

Cisco 계열 장비에서는 필요한 경우 다음 확인 명령어 결과를 함께 보관한다.

```cisco
show ip interface brief
show vlan brief
show interfaces trunk
show ip route
show ip ospf neighbor
show spanning-tree
show running-config
```

<br>

## 검증 항목

GNS3 네트워크 구성 완료 후 다음 항목을 확인한다.

1. VLAN 10 내부 통신
2. VLAN 30 내부 통신
3. VLAN 10 ↔ VLAN 30 통신
4. PC → DB 통신
5. PC → EMR 통신
6. DB / EMR → Gateway 통신
7. 외부망 방향 통신
8. OSPF Neighbor 상태
9. Routing Table 정상 여부
10. Trunk 및 VLAN 전달 상태
11. Firewall 정상 상태 통신
12. Firewall 장애 시 HA 전환
13. 장애 복구 후 정상 통신

검증 시 단순히 `성공`이라고 기록하지 않고 가능한 경우 실제 명령어와 결과를 함께 보관한다.

예시:

```cisco
show ip route
show ip ospf neighbor
```

```text
Result: 정상
OSPF Neighbor: FULL
Routing Table: 정상 학습
```

<br>

## GNS3 재구성 순서

새 GNS3 환경에서 네트워크를 다시 구성할 경우 다음 순서를 기준으로 한다.

1. 필요한 GNS3 Appliance / Image를 준비한다.
2. Repository의 Topology 자료를 기준으로 장비를 배치한다.
3. 장비 간 Interface 연결 관계를 동일하게 구성한다.
4. Access Switch의 VLAN 및 Port를 설정한다.
5. Core Switch의 VLAN, Trunk, SVI를 설정한다.
6. Routing 및 OSPF를 구성한다.
7. Firewall의 WAN/LAN Interface를 구성한다.
8. Firewall NAT / Rule / HA 설정을 적용한다.
9. PC, DB, EMR Host의 IP 및 Gateway를 설정한다.
10. 각 구간별 Ping을 확인한다.
11. VLAN, Routing, OSPF 및 Firewall 상태를 확인한다.
12. End-to-End 통신과 장애 전환을 검증한다.

<br>

## GNS3 Project 파일

GNS3 Project 원본을 별도로 보관하는 경우 해당 Project가 사용하는 Appliance/Image와 GNS3 버전을 함께 기록한다.

IOS/Image 파일은 라이선스 및 용량 문제로 GitHub Repository에 직접 포함하지 않는 것을 원칙으로 한다.

따라서 새로운 환경에서는 필요한 Image를 별도로 준비하고 Repository의 토폴로지 및 설정 문서를 기준으로 네트워크를 복원한다.

<br>

## Git 제외 및 별도 관리 항목

다음 파일 또는 정보는 Repository에 직접 저장하지 않는다.

- Cisco IOS 등 라이선스가 필요한 Image
- VM Disk Image
- 대용량 GNS3 Runtime 파일
- 실제 비밀번호
- Private Key
- Credential
- Secret
- Packet Capture 중 민감정보가 포함된 파일

설정 파일에 credential이 존재하는 경우 placeholder로 변경한다.

```text
<REDACTED>
<SECRET>
<PASSWORD>
```

<br>

## 안전 원칙

- GNS3 설정과 실제 Physical Network 설정을 구분해서 관리한다.
- 기존 GNS3 Project를 문서화하기 위해 장비 설정을 임의로 초기화하지 않는다.
- `running-config`를 확인한 후 문서를 작성한다.
- 실제 사용한 명령어와 검증 결과를 기준으로 기록한다.
- IOS/Image 파일은 Repository에 직접 업로드하지 않는다.
- GitHub 업로드 전 credential 및 민감정보 포함 여부를 확인한다.
