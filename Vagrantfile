# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.ssh.insert_key = false
  #config.vm.synced_folder './', '/vagrant', type: 'nfs'
  config.vm.provision "shell", path: "puppet/scripts/bootstrap.sh"
  
  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :machine
  end
  
  num_compute_nodes = (ENV['DEVSTACK_NUM_COMPUTE_NODES'] || 2).to_i

  # ip configuration
  control_ip = "192.168.50.20"
  compute_ip_base = "192.168.50."
  neutron_ex_ip = "192.168.111.10"
  compute_ex_ip_base = "192.168.111."
  compute_ips = num_compute_nodes.times.collect { |n| compute_ip_base + "#{n+21}" }
  compute_ex_ips = num_compute_nodes.times.collect { |n| compute_ex_ip_base + "#{n+11}" }

  config.vm.provision "puppet" do |puppet|
      puppet.hiera_config_path = "puppet/hiera.yaml"
      puppet.working_directory = "/vagrant/puppet"
      puppet.manifests_path = "puppet/manifests"
      puppet.manifest_file  = "base.pp"
      #puppet.options = "--verbose --debug"
  end

  # Devstack Controller
  config.vm.define "devstack-control", primary: true do |control|
    control.vm.box = "ubuntu/trusty64"
    control.vm.hostname = "devstack-control"
    ## control.vm.network "public_network", ip: "#{control_ip}", bridge: "tap1"
    control.vm.network "private_network", ip: "#{control_ip}"
    ## control.vm.network "forwarded_port", guest: 8080, host: 8081
    control.vm.network "private_network", ip: "#{neutron_ex_ip}", :libvirt__network_name => "mylocalnet"
    control.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--cpus", "6"]
      vb.customize ["modifyvm", :id, "--memory", "4096"]
      vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
      vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
      vb.customize ["modifyvm", :id, "--nictype3", "virtio"]
      vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
      vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
    end
    control.vm.provider :libvirt do |lv|
      lv.cpus = 6
      lv.memory = 4096
      lv.nested = true
      lv.cpu_mode = "host-passthrough"
      lv.nic_model_type = "virtio"
    end
    control.vm.provider "vmware_fusion" do |vf|
      vf.vmx["memsize"] = "4096"
    end
    control.vm.provision "puppet" do |puppet|
      puppet.hiera_config_path = "puppet/hiera.yaml"
      puppet.working_directory = "/vagrant/puppet"
      puppet.manifests_path = "puppet/manifests"
      puppet.manifest_file  = "devstack-control.pp"
      #puppet.options = "--verbose --debug"
    end
  end

  # Devstack Compute Nodes
  num_compute_nodes.times do |n|
    config.vm.define "devstack-compute-#{n+1}", autostart: true do |compute|
      compute_ip = compute_ips[n]
      compute_ex_ip = compute_ex_ips[n]
      compute_index = n+1
      compute.vm.box = "ubuntu/trusty64"
      compute.vm.hostname = "devstack-compute-#{compute_index}"
      ## compute.vm.network "public_network", ip: "#{compute_ip}", bridge: "tap1"
      compute.vm.network "private_network", ip: "#{compute_ip}"
      compute.vm.network "private_network", ip: "#{compute_ex_ip}", :libvirt__network_name => "mylocalnet"
      compute.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--cpus", "6"]
        vb.customize ["modifyvm", :id, "--memory", "8192"]
        vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
        vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
        vb.customize ["modifyvm", :id, "--nictype3", "virtio"]
        vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
        vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
      end
      compute.vm.provider :libvirt do |lv|
        lv.cpus = 6
        lv.memory = 8192
        lv.nested = true
        lv.cpu_mode = "host-passthrough"
        lv.nic_model_type = "virtio"
      end
      compute.vm.provider "vmware_fusion" do |vf|
        vf.vmx["memsize"] = "4096"
      end
      compute.vm.provision "puppet" do |puppet|
        puppet.hiera_config_path = "puppet/hiera.yaml"
        puppet.working_directory = "/vagrant/puppet"
        puppet.manifests_path = "puppet/manifests"
        puppet.manifest_file  = "devstack-compute.pp"
        #puppet.options = "--verbose --debug"
      end
    end
  end

end
