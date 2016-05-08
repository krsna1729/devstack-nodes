$deps = [
    'python-setuptools',
    'sshpass',
]

file { '/home/vagrant/.ssh/id_rsa':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    source  => '/vagrant/insecure_private_key',
    mode    => 600,
}


vcsrepo {'/home/vagrant/devstack':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack-dev/devstack.git',
    revision => 'stable/mitaka',
    before   => File['/home/vagrant/devstack/local.conf'],
}

package { $deps:
    ensure   => installed,
}

vcsrepo {'/home/vagrant/networking-onos':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack/networking-onos.git',
    revision => 'master',
    before   => File['/home/vagrant/networking-onos/etc/conf_onos.ini'],
    require  => Package[$deps]
}

$hosts = hiera('hosts')

file { '/home/vagrant/devstack/local.conf':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    content => template('/vagrant/puppet/templates/control.local.conf.erb'),
}

file { '/home/vagrant/network-cfg.json':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    content => template('/vagrant/puppet/templates/network-cfg.json.erb'),
}

file { '/home/vagrant/networking-onos/etc/conf_onos.ini':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    content => template('/vagrant/puppet/templates/conf_onos.ini.erb'),
}

exec { 'Install ONOS neutron plugin':
    command => "python setup.py install",
    cwd     => '/home/vagrant/networking-onos',
    creates => "/usr/local/lib/python2.7/dist-packages/networking_onos-2016.1.0-py2.7.egg-infoo",
    user    => 'root',
    path    => $::path,
    timeout => 0,
    require => [File['/home/vagrant/networking-onos/etc/conf_onos.ini'], Package[$deps]]
}


$ctl_ip=$hosts['devstack-control']['ipaddress']


class { 'docker':
  docker_users => ['vagrant'],
  #version => 'latest',
}


docker::run { 'onos1':
  image    => 'onosproject/onos',
  detach   => true,
  tty      => true,
  env      => ["ONOS_IP=$ctl_ip"],
  name     => 'onos1',
# pull_on_start   => true,
  volumes   => ['/home/vagrant/.ssh:/root/.ssh'],
  extra_parameters => [ '--net=host' ],
  require => Class['docker'],
}

exec { 'Activate ONOS Apps':
    command => "sleep 20 && sshpass -p karaf ssh -o StrictHostKeyChecking=no -p 8101 karaf@${ctl_ip} 'app activate org.onosproject.drivers.ovsdb org.onosproject.openflow-base org.onosproject.lldpprovider org.onosproject.cordvtn'",
    user    => 'vagrant',
    path    => $::path,
    timeout => 0,
    require => [Docker::Run['onos1'], Package[$deps]],
    logoutput => true,
}

exec { 'Push CORD VTN Config':
    command => "sleep 20 && curl --user onos:rocks -X POST -H \"Content-Type: application/json\" http://${ctl_ip}:8181/onos/v1/network/configuration/ -d @/home/vagrant/network-cfg.json",
    user    => 'vagrant',
    path    => $::path,
    timeout => 0,
    logoutput => true,
    require => [Exec['Activate ONOS Apps']]
}

/*
exec { 'onos1':
    command => "docker pull onosproject/onos && docker run -e ONOS_IP=${ctl_ip} -v /home/vagrant/.ssh:/root/.ssh --net=host -t -d --name onos1 onosproject/onos > onos1",
    user    => 'root',
    cwd     => '/home/vagrant/',
    path    => $::path,
    timeout => 0,
    creates => '/home/vagrant/onos1',
    require => Class['docker'],
    logoutput => true,
}

exec {'Install Openstack':
   command => "/bin/bash ./stack.sh",
   user    => 'vagrant',
   cwd     => '/home/vagrant/devstack',
   path    => $::path,
   timeout => 0,
   require => [File['/home/vagrant/devstack/local.conf'], Exec['Install ONOS neutron plugin']]
}
*/
