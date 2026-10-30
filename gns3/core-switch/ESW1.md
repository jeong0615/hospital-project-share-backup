<br>

## 장비 요약

- Hostname: `ESW1`
- VLAN10: `IP_REDACTED/24 (VIP: IP_REDACTED)`
- VLAN30: `IP_REDACTED/24 (VIP: IP_REDACTED)`
- VLA100: `IP_REDACTED/24 (VIP: IP_REDACTED)`
- HSRP Priority: `110 (All Groups)`
- HSRP State: `Active (Preempt Enabled)`
- Routing: `Enabled (Static Default Route: IP_REDACTED/0 via IP_REDACTED)`
- Spanning Tree: `Enabled (PortFast on Access Ports)`

<br>

## Running Config

```text
conf t
hostname ESW1
ip routing
vlan 10
vlan 30
vlan 100
exit
ip dhcp excluded-address IP_REDACTED IP_REDACTED
ip dhcp pool LAN10
network IP_REDACTED IP_REDACTED
default-router IP_REDACTED
dns-server IP_REDACTED
exit
interface vlan 10
ip address IP_REDACTED IP_REDACTED
standby 10 ip IP_REDACTED
standby 10 priority 110
standby 10 preempt
exit
interface vlan 30
ip address IP_REDACTED IP_REDACTED
standby 30 ip IP_REDACTED
standby 30 priority 110
standby 30 preempt
exit
interface vlan 100
ip address IP_REDACTED IP_REDACTED
standby 100 ip IP_REDACTED
standby 100 priority 110
standby 100 preempt
exit
interface range f1/0
switchport mode access
switchport access vlan 100
spanning-tree portfast
exit
interface range f1/14
switchport mode access
switchport access vlan 100
spanning-tree portfast
exit
interface f1/1
switchport mode access
switchport access vlan 10
spanning-tree portfast
exit
interface f1/2
switchport mode access
switchport access vlan 30
spanning-tree portfast
exit
interface f1/15
switchport trunk encapsulation dot1q
switchport mode trunk
exit
ip route IP_REDACTED IP_REDACTED IP_REDACTED
end
wr
```
