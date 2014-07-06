class { '::puppet::main':
  config => '/tmp/puppet.conf',
} ->
puppet::config { 'foo':
  section => 'bar',
  value   => 'baz',
}
