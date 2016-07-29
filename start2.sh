sudo rm -rf /tmp/bess
sudo mkdir -p /tmp/bess
#screen -S bess -d -m "sudo /opt/bess/bin/bessd -fk > bess.log"
sudo /opt/bess/bin/bessd -k

DPID=$(hostname | cut -d- -f3)
/opt/bess/bin/bessctl daemon reset
#/vagrant/bess_of_agent.py -d $DPID -c '192.168.60.20' 
/vagrant/bess_of_agent.py -f /vagrant/OVS-OF-compute-2.pcap -i 192.168.50.22

