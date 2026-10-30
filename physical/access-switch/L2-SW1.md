# Cisco Catalyst 2950 L2 Switch

<br>

## 장비 요약

- Hostname: `L2-SW`
- Management IP: `IP_REDACTED/29`
- Default Gateway: `IP_REDACTED`
- Fa0/3: Router Uplink / VLAN 1,100 Trunk
- Fa0/22: Web VLAN20 Access
- Fa0/23: L3-SW1(3550) Trunk
- Fa0/24: L3-SW2(3560) Trunk
- Spanning Tree: Rapid-PVST
- Remote Management: Telnet / Local Login

<br>

## Running Config

```text
version 12.1
no service pad
service timestamps debug uptime
service timestamps log uptime
service password-encryption
hostname L2-Switch
enable secret CREDENTIAL_REDACTED <REDACTED>
username admin password CREDENTIAL_REDACTED <REDACTED>
ip subnet-zero

spanning-tree mode rapid-pvst
no spanning-tree optimize bpdu transmission
spanning-tree extend system-id

interface FastEthernet0/1

interface FastEthernet0/2

interface FastEthernet0/3
 description UPLINK-TO-ROUTER
 switchport trunk allowed vlan 1,100
 switchport mode trunk

interface FastEthernet0/4
 switchport mode trunk

interface FastEthernet0/5

interface FastEthernet0/6

interface FastEthernet0/7

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
 description WEB-USB-LAN-VLAN20
 switchport access vlan 20
 switchport mode access

interface FastEthernet0/23
 description UPLINK-TO-3550
 switchport trunk allowed vlan 10,20,30,100
 switchport mode trunk

interface FastEthernet0/24
 description UPLINK-TO-3560
 switchport trunk allowed vlan 10,20,30,100
 switchport mode trunk

interface GigabitEthernet0/1

interface GigabitEthernet0/2

interface Vlan1
 ip address IP_REDACTED IP_REDACTED
 no ip route-cache

ip default-gateway IP_REDACTED
ip http server

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
Vlan1                      IP_REDACTED        YES NVRAM  up                    up
FastEthernet0/1            unassigned      YES unset  down                  down
FastEthernet0/2            unassigned      YES unset  up                    up
FastEthernet0/3            unassigned      YES unset  up                    up
FastEthernet0/4            unassigned      YES unset  up                    up
FastEthernet0/5            unassigned      YES unset  up                    up
FastEthernet0/6            unassigned      YES unset  down                  down
FastEthernet0/7            unassigned      YES unset  down                  down
FastEthernet0/8            unassigned      YES unset  down                  down
FastEthernet0/9            unassigned      YES unset  down                  down
FastEthernet0/10           unassigned      YES unset  down                  down
FastEthernet0/11           unassigned      YES unset  down                  down
FastEthernet0/12           unassigned      YES unset  down                  down
FastEthernet0/13           unassigned      YES unset  down                  down
FastEthernet0/14           unassigned      YES unset  down                  down
FastEthernet0/15           unassigned      YES unset  down                  down
FastEthernet0/16           unassigned      YES unset  down                  down
FastEthernet0/17           unassigned      YES unset  down                  down
FastEthernet0/18           unassigned      YES unset  down                  down
FastEthernet0/19           unassigned      YES unset  down                  down
FastEthernet0/20           unassigned      YES unset  down                  down
FastEthernet0/21           unassigned      YES unset  down                  down
FastEthernet0/22           unassigned      YES unset  up                    up
FastEthernet0/23           unassigned      YES unset  up                    up
FastEthernet0/24           unassigned      YES unset  up                    up
GigabitEthernet0/1         unassigned      YES unset  down                  down
GigabitEthernet0/2         unassigned      YES unset  down                  down
```
