$deps = [
    'python-setuptools'
]

vcsrepo {'/home/vagrant/devstack':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack-dev/devstack.git',
    revision => 'stable/kilo',
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
    creates => "/home/vagrant/networking-onos/networking_onos.egg-info",
    user    => 'root',
    path    => $::path,
    timeout => 0,
    require => File['/home/vagrant/networking-onos/etc/conf_onos.ini']
}
