$deps = [
    'curl',
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
    "linux-image-extra-$kernelrelease",
    'python-dev',
    'python-setuptools',
    'libgraph-easy-perl',
    'openvswitch-switch',
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

exec { 'Install PIP':
    command => 'curl "https://bootstrap.pypa.io/get-pip.py" | python',
    user    => 'root',
    path    => $::path,
    timeout => 0,
    require => Package[$deps]
}

vcsrepo {'/vagrant/nova':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack/nova.git',
    revision => 'stable/mitaka',
    require  => Package[$deps]
}

patch::directory { '/vagrant/nova':
  diff_source => '/vagrant/nova_mitaka_bess.patch',
  strip => 1,
  require => Vcsrepo['/vagrant/nova']
}

