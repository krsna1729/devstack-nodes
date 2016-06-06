vcsrepo {'/home/vagrant/devstack':
    ensure   => present,
    provider => git,
    user     => 'vagrant',
    source   => 'https://github.com/openstack-dev/devstack.git',
    revision => 'stable/mitaka',
    before   => File['/home/vagrant/devstack/local.conf'],
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
  strip => 1,
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

exec { 'Install PIP':
    command => 'curl "https://bootstrap.pypa.io/get-pip.py" | python',
    user    => 'root',
    path    => $::path,
    timeout => 0,
}

exec { 'Install twink':
    command => 'sleep 5 && pip install https://github.com/krsna1729/twink/archive/master.zip',
    user    => 'root',
    path    => $::path,
    timeout => 0,
    require => Exec['Install PIP'],
}

$hosts = hiera('hosts')

file { '/home/vagrant/devstack/local.conf':
    ensure  => present,
    owner   => 'vagrant',
    group   => 'vagrant',
    content => template('/vagrant/puppet/templates/compute.local.conf.erb'),
    before   => Exec['Download Open vSwitch'],
}

$ovs_version = '2.3.2'


exec {'Download Open vSwitch':
    command => "wget http://openvswitch.org/releases/openvswitch-${ovs_version}.tar.gz",
    cwd     => "/vagrant",
    creates => "/vagrant/openvswitch-${ovs_version}.tar.gz",
    path    => $::path,
    user    => 'vagrant'
}

exec { 'Extract Open vSwitch':
    command => "tar -xvf openvswitch-${ovs_version}.tar.gz",
    cwd     => '/vagrant',
    creates => "/vagrant/openvswitch-${ovs_version}",
    user    => 'vagrant',
    path    => $::path,
    timeout => 0,
    require => Exec['Download Open vSwitch']
}

exec { 'Compile Open vSwitch':
    environment => ["DEB_BUILD_OPTIONS='parallel=6 nocheck'"],
    command => "fakeroot debian/rules binary",
    cwd     => "/vagrant/openvswitch-${ovs_version}",
    creates => "/vagrant/openvswitch-common_${ovs_version}-1_amd64.deb",
    user    => 'root',
    path    => $::path,
    timeout => 0,
    require => [Exec['Extract Open vSwitch']]
}

package { 'openvswitch-common':
    ensure   => installed,
    provider => dpkg,
    source   => "/vagrant/openvswitch-common_${ovs_version}-1_amd64.deb",
    require  => Exec['Compile Open vSwitch']
}

package { 'openvswitch-switch':
    ensure   => installed,
    provider => dpkg,
    source   => "/vagrant/openvswitch-switch_${ovs_version}-1_amd64.deb",
    require  => Package['openvswitch-common']
}

package { 'openvswitch-datapath-dkms':
    ensure   => installed,
    provider => dpkg,
    source   => "/vagrant/openvswitch-datapath-dkms_${ovs_version}-1_all.deb",
    require  => Package['openvswitch-switch']
}

package { 'openvswitch-pki':
    ensure   => installed,
    provider => dpkg,
    source   => "/vagrant/openvswitch-pki_${ovs_version}-1_all.deb",
    require  => Package['openvswitch-datapath-dkms'],
    before   => Exec['Set OVSDB to listen on 6640']
}

exec { 'Set OVSDB to listen on 6640':
    command => "ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640 && netstat -ntl",
    user    => 'root',
    path    => $::path,
    timeout => 0,
    logoutput => true,
#   require => [Package['openvswitch-common'], Package['openvswitch-switch']]
}
/*
exec {'Install Openstack':
   command => "/bin/bash ./stack.sh",
   user    => 'vagrant',
   cwd     => '/home/vagrant/devstack',
   path    => $::path,
   timeout => 0,
   require => File['/home/vagrant/devstack/local.conf'],
}
*/
