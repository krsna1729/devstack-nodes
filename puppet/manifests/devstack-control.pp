$deps = [
    'python-setuptools'
]

vcsrepo {'/home/vagrant/devstack':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack-dev/devstack.git',
    revision => 'stable/mitaka',
    before   => File['/home/vagrant/devstack/local.conf'],
}

vcsrepo {'/home/vagrant/networking-onos':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack/networking-onos.git',
    revision => 'master',
}

$hosts = hiera('hosts')

file { '/home/vagrant/devstack/local.conf':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    content => template('/vagrant/puppet/templates/control.local.conf.erb'),
}
