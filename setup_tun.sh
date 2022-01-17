./delete_tun.sh
sudo ip tuntap add mode tap dev tun6996
sudo ip link set tun6996 up
sudo ip addr add dev tun6996 local 10.0.0.1 remote 10.0.0.2
