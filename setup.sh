#BESS and OF agent related
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p -m 777 /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
sudo modprobe uio
sudo modprobe uio_pci_generic

#sudo service openvswitch-switch stop
sudo killall ovs-vswitchd

DPDK_NIC_BIND=$(ls -1 /opt/bess/deps/dpdk*/tools/dpdk-devbind.py | head -n1);
echo $DPDK_NIC_BIND
eval "$DPDK_NIC_BIND --status"
eval "sudo $DPDK_NIC_BIND -b uio_pci_generic 00:07.0"
eval "$DPDK_NIC_BIND --status"

