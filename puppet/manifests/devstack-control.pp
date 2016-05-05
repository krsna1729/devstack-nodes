$deps = [
    'python-setuptools'
]

file { '/home/vagrant/.ssh/id_rsa':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    source  => '/vagrant/insecure_private_key',
    mode    => 600,
    before  => Exec['ONOS Container'],
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
    require => File['/home/vagrant/networking-onos/etc/conf_onos.ini']
}


$ctl_ip=$hosts['devstack-control']['ipaddress']


class { 'docker':
  docker_users => ['vagrant'],
  #version => 'latest',
}

/*
docker::run { 'onos1':
  image    => 'onosproject/onos',
  detach   => true,
  tty      => true,
  env      => ['ONOS_IP=$ctl_ip'],
  net      => 'host',
  name     => 'onos1',
  pull_on_start   => true,
  volumes   => ['/home/vagrant/.ssh:/root/.ssh'],
  remove_container_on_start => true,
  remove_volume_on_start    => false,
  remove_container_on_stop  => true,
  remove_volume_on_stop     => false,
}
*/


exec { 'ONOS Container':
    command => "docker pull onosproject/onos && docker run -e ONOS_IP=${ctl_ip} -v /home/vagrant/.ssh:/root/.ssh --net=host -t -d --name onos1 onosproject/onos > onos1",
    user    => 'root',
    cwd     => '/home/vagrant/',
    path    => $::path,
    timeout => 0,
    creates => '/home/vagrant/onos1',
    require => Class['docker'],
    logoutput => true,
}

