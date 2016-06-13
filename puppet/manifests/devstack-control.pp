$deps = [
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

patch::directory { '/home/vagrant/networking-onos':
  diff_source => '/vagrant/networking_onos_bess.patch',
  strip => 1,
  before => Exec['Install ONOS neutron plugin'],
  require => Vcsrepo['/home/vagrant/networking-onos']
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
    require => [File['/home/vagrant/networking-onos/etc/conf_onos.ini']]
}

$ctl_ip=$hosts['devstack-control']['ipaddress']

docker::run { 'onos1':
  image    => 'onosproject/onos@sha256:79e344460ce0f8755f68e5d09ef1c8fa08014f585e8a41b57a70b2f9bb388ad8',
  detach   => true,
  tty      => true,
  env      => ["ONOS_IP=$ctl_ip"],
  name     => 'onos1',
  volumes   => ['/home/vagrant/.ssh:/root/.ssh'],
  extra_parameters => [ '--net=host' ],
}

exec { 'Activate ONOS Apps':
    command => "sshpass -p karaf ssh -o StrictHostKeyChecking=no -p 8101 karaf@${ctl_ip} 'app activate org.onosproject.drivers.ovsdb org.onosproject.openflow-base org.onosproject.lldpprovider org.onosproject.cordvtn'",
    user    => 'vagrant',
    path    => $::path,
    timeout => 0,
    require => [Docker::Run['onos1'], Package[$deps]],
    logoutput => true,
    tries => 3,
    try_sleep   => 15,
}

exec { 'Push CORD VTN Config':
    command => "sleep 20 && curl --user onos:rocks -X POST -H \"Content-Type: application/json\" http://${ctl_ip}:8181/onos/v1/network/configuration/ -d @/home/vagrant/network-cfg.json",
    user    => 'vagrant',
    path    => $::path,
    timeout => 0,
    logoutput => true,
    require => [Exec['Activate ONOS Apps'], File['/home/vagrant/network-cfg.json']],
    tries => 3,
    try_sleep   => 15,
}
