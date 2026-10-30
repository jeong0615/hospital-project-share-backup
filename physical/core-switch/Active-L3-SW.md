# [Active L3 Switch] Cisco Catalyst 3560

<br>

## 장비 요약

- Hostname: `Active-L3-Switch`
- Management/Core IP: `IP_REDACTED`
- VLAN20: `IP_REDACTED/24`
- VLAN100: `IP_REDACTED/24`
- HSRP Priority: `250`
- HSRP State: Active
- Routing: RIP v2, Default Route
- Spanning Tree: Rapid-PVST
- EtherChannel: LACP Port-channel12
- Security: WEB-FILTER Extended ACL
- Remote Management: Telnet / Local Login

<br>

## Running Config

```text
version 12.2
no service pad
service timestamps debug uptime
service timestamps log uptime
service password-encryption
hostname L3-SW2
enable password CREDENTIAL_REDACTED <REDACTED>
username sw1 password CREDENTIAL_REDACTED <REDACTED>
username admin password CREDENTIAL_REDACTED <REDACTED>
no aaa new-model
vtp domain hoseo
vtp mode transparent

track 1 interface Port-channel12 line-protocol
ip subnet-zero
ip routing

no file verify auto

spanning-tree mode rapid-pvst
spanning-tree extend system-id
spanning-tree vlan 20,100 priority 24576

vlan internal allocation policy ascending

vlan 20
 name 2F

vlan 40,50,60,70

vlan 100
 name CORE-UPLINK

interface Port-channel1

interface Port-channel12
 switchport trunk encapsulation dot1q
 switchport mode trunk

interface FastEthernet0/1

interface FastEthernet0/2
 no switchport
 ip address IP_REDACTED IP_REDACTED
 ip rip advertise 3

interface FastEthernet0/3

interface FastEthernet0/4
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 12 mode active

interface FastEthernet0/5
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 12 mode active

interface FastEthernet0/6
 switchport trunk encapsulation dot1q
 switchport mode trunk

interface FastEthernet0/7
 switchport trunk encapsulation dot1q
 switchport mode trunk

interface FastEthernet0/8

interface FastEthernet0/9

interface FastEthernet0/10

interface FastEthernet0/11

interface FastEthernet0/12

interface FastEthernet0/13

interface FastEthernet0/14

interface FastEthernet0/15

interface FastEthernet0/16

interface FastEthernet0/17

interface FastEthernet0/18

interface FastEthernet0/19

interface FastEthernet0/20

interface FastEthernet0/21

interface FastEthernet0/22
 description UPLINK-TO-2950
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 20,100
 switchport mode trunk

interface FastEthernet0/23

interface FastEthernet0/24

interface GigabitEthernet0/1

interface GigabitEthernet0/2

interface Vlan1
 no ip address

interface Vlan20
 ip address IP_REDACTED IP_REDACTED
 ip access-group WEB-FILTER in
 ip rip advertise 3
 standby 20 ip IP_REDACTED
 standby 20 timers 1 3
 standby 20 priority 250
 standby 20 preempt delay minimum 5

interface Vlan100
 ip address IP_REDACTED IP_REDACTED
 ip rip advertise 3

router rip
 version 2
 timers basic 3 18 150 300
 network IP_REDACTED
 network IP_REDACTED
 network IP_REDACTED
 no auto-summary

ip classless
ip route IP_REDACTED IP_REDACTED IP_REDACTED
ip http server

ip access-list extended WEB-FILTER
 permit tcp IP_REDACTED IP_REDACTED host IP_REDACTED eq 3306
 permit tcp IP_REDACTED IP_REDACTED host IP_REDACTED eq 5000
 deny   ip IP_REDACTED IP_REDACTED IP_REDACTED IP_REDACTED
 deny   ip IP_REDACTED IP_REDACTED IP_REDACTED IP_REDACTED
 permit ip any any

control-plane

line con 0
 speed 115200

line vty 0 4
 password 7 <REDACTED>
 login local
 transport input telnet

line vty 5 15
 no login

end
```

<br>

## Interface Status

```text
Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  unassigned      YES NVRAM  up                    up
Vlan20                 IP_REDACTED  YES NVRAM  up                    up
Vlan100                IP_REDACTED   YES NVRAM  up                    up
FastEthernet0/1        unassigned      YES unset  down                  down
FastEthernet0/2        IP_REDACTED       YES NVRAM  down                  down
FastEthernet0/3        unassigned      YES unset  up                    up
FastEthernet0/4        unassigned      YES unset  down                  down
FastEthernet0/5        unassigned      YES unset  down                  down
FastEthernet0/6        unassigned      YES unset  down                  down
FastEthernet0/7        unassigned      YES unset  down                  down
FastEthernet0/8        unassigned      YES unset  down                  down
FastEthernet0/9        unassigned      YES unset  down                  down
FastEthernet0/10       unassigned      YES unset  down                  down
FastEthernet0/11       unassigned      YES unset  down                  down
FastEthernet0/12       unassigned      YES unset  down                  down
FastEthernet0/13       unassigned      YES unset  down                  down
FastEthernet0/14       unassigned      YES unset  down                  down
FastEthernet0/15       unassigned      YES unset  down                  down
FastEthernet0/16       unassigned      YES unset  down                  down
FastEthernet0/17       unassigned      YES unset  down                  down
FastEthernet0/18       unassigned      YES unset  down                  down
FastEthernet0/19       unassigned      YES unset  down                  down
FastEthernet0/20       unassigned      YES unset  down                  down
FastEthernet0/21       unassigned      YES unset  down                  down
FastEthernet0/22       unassigned      YES unset  up                    up
FastEthernet0/23       unassigned      YES unset  down                  down
FastEthernet0/24       unassigned      YES unset  down                  down
GigabitEthernet0/1     unassigned      YES unset  down                  down
GigabitEthernet0/2     unassigned      YES unset  down                  down
Port-channel1          unassigned      YES unset  down                  down
Port-channel12         unassigned      YES unset  down                  down
```

<br>

## HSRP Status

```text
VLAN20
- Virtual IP: IP_REDACTED
- Local IP: IP_REDACTED
- Priority: 250
- State: Active
- Standby Router: IP_REDACTED
```
