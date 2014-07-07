class { '::puppetconfig::main':
  config => '/tmp/puppet.conf',
} ->
puppetconfig::config { 'foo':
  section => 'bar',
  value   => 'baz',
}
