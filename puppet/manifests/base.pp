$deps = [
    'autoconf',
    'automake',
    'curl',
    'debhelper',
    'gcc',
    'libssl-dev',
    'git',
    'tcpdump',
    'wget',
    'tar',
    'libxml2-dev',
    'libxslt1-dev',
    'xbase-clients',
    'emacs',
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

