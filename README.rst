devstack-nodes
==============

This repo provides a Vagrantfile with provisioning that one can use to easily
get a cluster of nodes configured with DevStack.

Modify the CPU and memory allocation in the Vagrantfile as required::

    control.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--cpus", "6"]
        vb.customize ["modifyvm", :id, "--memory", "4096"]
    ...    
    compute.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--cpus", "6"]
        vb.customize ["modifyvm", :id, "--memory", "2048"]

Testing
-------

One time::

    vagrant plugin install vagrant-hostmanager
    vagrant plugin install vagrant-cachier
    
    cd devstack-nodes
    cp $HOME/.vagrant.d/insecure_private_key .
    
A Vagrantfile is provided to easily create a DevStack environment to test with::

    vagrant up 
    OR
    vagrant up --no-provision
    ls .vagrant/machines/ | xargs -n 1 -P 3 vagrant provision
    
If you would like more than two compute nodes, you can set the following environment variable::

    export DEVSTACK_NUM_COMPUTE_NODES=3
