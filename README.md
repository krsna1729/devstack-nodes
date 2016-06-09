devstack-nodes
==============

This repo provides a Vagrantfile with provisioning that one can use to easily
get a cluster of nodes configured with DevStack.

Modify the CPU and memory allocation in the Vagrantfile as required:

    control.vm.provider :libvirt do |lv|
        lv.cpus = 6
        lv.memory = 4096
    ...    
    compute.vm.provider :libvirt do |lv|
        lv.cpus = 6
        lv.memory = 8192

Testing
-------
Install Vagrant with libvirt provider. [Fedora](https://developer.fedoraproject.org/tools/vagrant/vagrant-libvirt.html). [Ubuntu](http://lost-and-found-narihiro.blogspot.com/2015/06/ubuntu-1404-install-latest-version-of.html).   
Make sure vagrant-mutate plugin is installed, if not captured by previous intallation procedure listed. NFS is used to speed up subsequent install times. If you dont want to use NFS comment out this line   
`config.vm.synced_folder './', '/vagrant', type: 'nfs'`

One time:

    vagrant plugin install vagrant-mutate
    vagrant box add ubuntu/trusty64
    vagrant mutate ubuntu/trusty64 libvirt
    vagrant plugin install vagrant-hostmanager
    vagrant plugin install vagrant-cachier
    
    cd devstack-nodes
    cp $HOME/.vagrant.d/insecure_private_key .
    
A Vagrantfile is provided to easily create a DevStack environment to test with. First time:

    vagrant up devstack-control --provider=libvirt
    vagrant up devstack-compute-1 --provider=libvirt 
    vagrant up devstack-compute-2 --provider=libvirt 

Later bringups can be done by:

    vagrant up --provider=libvirt 

If you would like more than two compute nodes, you can set the following environment variable::

    export DEVSTACK_NUM_COMPUTE_NODES=3

If you face any issues with NFS see if this [guide](https://developer.fedoraproject.org/tools/vagrant/vagrant-nfs.html) helps.
