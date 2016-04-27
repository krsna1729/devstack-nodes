devstack-nodes
==============

This repo provides a Vagrantfile with provisioning that one can use to easily
get a cluster of nodes configured with DevStack.

Testing
-------

A Vagrantfile is provided to easily create a DevStack environment to test with::

    vagrant up
    vagrant status

If you would like more than two compute node, you can set the following environment variable::

    export DEVSTACK_NUM_COMPUTE_NODES=3
