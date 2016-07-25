sudo rm -rf /tmp/bess
sudo mkdir -m 777 /tmp/bess
sudo /opt/bess/bin/bessd -k

DPID=$(hostname | cut -d- -f3)
/opt/bess/bin/bessctl daemon reset
/vagrant/bess_of_agent.py -d $DPID -c '192.168.60.20'

