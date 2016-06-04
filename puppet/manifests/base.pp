$deps = [
    'autoconf',
    'automake',
    'curl',
    'debhelper',
    'gcc',
    'libssl-dev',
    'libpcap-dev',
    'git',
    'tcpdump',
    'wget',
    'tar',
    'libxml2-dev',
    'libxslt1-dev',
    'xbase-clients',
    'python-dev',
    'python-setuptools',
    'linux-generic',
    'linux-headers-generic',
    'wireshark'
]

$hosts = hiera('hosts')

file { '/etc/hosts':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    content => template('/vagrant/puppet/templates/hosts.erb')
}

package { $deps:
    ensure   => installed,
}

vcsrepo {'/home/vagrant/nova':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack/nova.git',
    revision => 'stable/mitaka',
    require  => Package[$deps]
}

patch::directory { '/home/vagrant/nova':
  diff_source => '/vagrant/nova_mitaka_bess.patch',
  strip => 1,
  require => Vcsrepo['/home/vagrant/nova']
}

