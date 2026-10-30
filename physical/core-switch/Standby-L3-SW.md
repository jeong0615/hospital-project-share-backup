# [Standby L3 Switch] Cisco Catalyst 3550

<br>

## 장비 요약

- Hostname: `Standby-L3-SW`
- Management/Core IP: `IP_REDACTED`
- VLAN20: `IP_REDACTED/24`
- VLAN100: `IP_REDACTED/24`
- HSRP Priority: `200`
- HSRP State: Standby
- Routing: RIP v2, Static/Default Route
- Spanning Tree: Rapid-PVST
- EtherChannel: LACP Port-channel12
- Security: WEB-FILTER Extended ACL
- Remote Management: Telnet / Local Login

<br>

## Running Config

```text
version 12.1
no service pad
service timestamps debug uptime
service timestamps log uptime
service password-encryption
hostname Standby-L3-SW
enable secret CREDENTIAL_REDACTED <REDACTED>
username admin password CREDENTIAL_REDACTED <REDACTED>
ip subnet-zero
ip routing

ip ssh time-out 120
ip ssh authentication-retries 3

spanning-tree mode rapid-pvst
spanning-tree extend system-id
spanning-tree vlan 20 priority 28672
spanning-tree vlan 100 priority 28672

interface Port-channel12
 switchport trunk encapsulation dot1q
 switchport mode trunk
 no ip address

interface FastEthernet0/1
 switchport mode dynamic desirable
 no ip address
 shutdown

interface FastEthernet0/2
 switchport mode access
 no ip address
 shutdown

interface FastEthernet0/3
 switchport trunk encapsulation dot1q
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/4
 switchport trunk encapsulation dot1q
 switchport mode trunk
 no ip address
 channel-group 12 mode active
 channel-protocol lacp

interface FastEthernet0/5
 switchport trunk encapsulation dot1q
 switchport mode trunk
 no ip address
 channel-group 12 mode active
 channel-protocol lacp

interface FastEthernet0/6
 switchport trunk encapsulation dot1q
 switchport mode trunk
 no ip address

interface FastEthernet0/7
 switchport trunk encapsulation dot1q
 switchport mode access
 no ip address

interface FastEthernet0/8
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/9
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/10
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/11
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/12
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/13
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/14
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/15
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/16
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/17
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/18
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/19
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/20
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/21
 description UPLINK-TO-2950
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 20,100
 switchport mode trunk
 no ip address

interface FastEthernet0/22
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/23
 switchport mode dynamic desirable
 no ip address

interface FastEthernet0/24
 switchport mode dynamic desirable
 no ip address

interface GigabitEthernet0/1
 switchport mode dynamic desirable
 no ip address

interface GigabitEthernet0/2
 switchport mode dynamic desirable
 no ip address

interface Vlan1
 ip address IP_REDACTED IP_REDACTED

interface Vlan20
 ip address IP_REDACTED IP_REDACTED
 ip access-group WEB-FILTER in
 no ip redirects
 standby 20 ip IP_REDACTED
 standby 20 timers 1 3
 standby 20 priority 200
 standby 20 preempt
 standby 20 authentication <REDACTED>

interface Vlan100
 ip address IP_REDACTED IP_REDACTED

router rip
 version 2
 network IP_REDACTED
 network IP_REDACTED
 network IP_REDACTED
 no auto-summary

ip default-gateway IP_REDACTED
ip classless
ip route IP_REDACTED IP_REDACTED IP_REDACTED
ip route IP_REDACTED IP_REDACTED IP_REDACTED
ip http server

ip access-list extended WEB-FILTER
 permit tcp IP_REDACTED IP_REDACTED host IP_REDACTED eq 3306
 permit tcp IP_REDACTED IP_REDACTED host IP_REDACTED eq 5000
 deny   ip IP_REDACTED IP_REDACTED IP_REDACTED IP_REDACTED
 deny   ip IP_REDACTED IP_REDACTED IP_REDACTED IP_REDACTED
 permit ip any any

line con 0

line vty 0 4
 login local
 transport input telnet

line vty 5 15
 login

end
```

<br>

## Interface Status

```text
Interface                  IP-Address      OK? Method Status                Protocol
Vlan1                      IP_REDACTED  YES NVRAM  up                    up
Vlan20                     IP_REDACTED  YES NVRAM  up                    up
Vlan100                    IP_REDACTED   YES NVRAM  up                    up
FastEthernet0/1            unassigned      YES unset  administratively down down
FastEthernet0/2            unassigned      YES unset  administratively down down
FastEthernet0/3            unassigned      YES unset  down                  down
FastEthernet0/4            unassigned      YES unset  down                  down
FastEthernet0/5            unassigned      YES unset  down                  down
FastEthernet0/6            unassigned      YES unset  down                  down
FastEthernet0/7            unassigned      YES unset  down                  down
FastEthernet0/8            unassigned      YES unset  down                  down
FastEthernet0/9            unassigned      YES unset  down                  down
FastEthernet0/10           unassigned      YES unset  down                  down
FastEthernet0/11           unassigned      YES unset  down                  down
FastEthernet0/12           unassigned      YES unset  down                  down
FastEthernet0/13           unassigned      YES unset  up                    up
FastEthernet0/14           unassigned      YES unset  down                  down
FastEthernet0/15           unassigned      YES unset  down                  down
FastEthernet0/16           unassigned      YES unset  down                  down
FastEthernet0/17           unassigned      YES unset  down                  down
FastEthernet0/18           unassigned      YES unset  down                  down
FastEthernet0/19           unassigned      YES unset  down                  down
FastEthernet0/20           unassigned      YES unset  down                  down
FastEthernet0/21           unassigned      YES unset  up                    up
FastEthernet0/22           unassigned      YES unset  down                  down
FastEthernet0/23           unassigned      YES unset  down                  down
FastEthernet0/24           unassigned      YES unset  down                  down
GigabitEthernet0/1         unassigned      YES unset  down                  down
GigabitEthernet0/2         unassigned      YES unset  down                  down
Port-channel12             unassigned      YES unset  down                  down
```

<br>

## HSRP Status

```text
VLAN20
- Virtual IP: IP_REDACTED
- Local IP: IP_REDACTED
- Priority: 200
- State: Standby
- Active Router: IP_REDACTED
```
