#BESS and OF agent related
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p -m 777 /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
sudo modprobe uio
sudo modprobe uio_pci_generic

#sudo service openvswitch-switch stop
sudo killall ovs-vswitchd

/opt/bess/deps/dpdk-16.04/tools/dpdk_nic_bind.py --status
sudo /opt/bess/deps/dpdk-16.04/tools/dpdk_nic_bind.py -b uio_pci_generic 00:07.0
/opt/bess/deps/dpdk-16.04/tools/dpdk_nic_bind.py --status
sudo mkdir -m 777 /tmp/bess

