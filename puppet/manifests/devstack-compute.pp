vcsrepo {'/home/vagrant/devstack':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack-dev/devstack.git',
    revision => 'stable/mitaka',
    before   => File['/home/vagrant/devstack/local.conf'],
}

patch::directory { '/home/vagrant/devstack':
  diff_source => '/vagrant/devstack_mitaka.patch',
  strip      => 1,
  require    => Vcsrepo['/home/vagrant/devstack'],
}

vcsrepo {'/opt/bess':
    ensure   => present,
    provider => git,
    user     => 'root',
    owner    => 'vagrant',
    group    => 'vagrant',
    source   => 'https://github.com/NetSys/bess.git',
    revision => 'develop',
    before   => Exec['Compile BESS'],
}

patch::directory { '/opt/bess':
  diff_source => '/vagrant/bess_vagrant_testing.patch',
  strip      => 1,
  before     => Exec['Compile BESS'],
  require    => Vcsrepo['/opt/bess'],
}

exec { 'Compile BESS':
    command => "python build.py",
    cwd     => '/opt/bess',
    creates => '/opt/bess/bin/bessd',
    user    => 'vagrant',
    path    => $::path,
    timeout => 0,
}

exec { 'Install twink':
    command => 'pip install https://github.com/krsna1729/twink/archive/master.zip',
    user    => 'root',
    path    => $::path,
    timeout => 0,
}

exec { 'Install Scapy':
    command => 'pip install scapy',
    user    => 'root',
    path    => $::path,
    timeout => 0,
}

$hosts = hiera('hosts')

file { '/home/vagrant/devstack/local.conf':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    content => template('/vagrant/puppet/templates/compute.local.conf.erb'),
}

exec { 'Set OVSDB to listen on 6640':
    command => "ovs-vsctl show && ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640 && netstat -tuln | grep 6640",
    user    => 'root',
    path    => $::path,
    timeout => 0,
    logoutput => true,
}
