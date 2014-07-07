class puppetconfig::params::main {
  $archive_file_server = 'master.puppetlabs.vm'
  $archive_files       = 'true'
  $certname            = 'master.puppetlabs.vm'
  $config              = '/etc/puppetlabs/puppet/puppet.conf'
  $dns_alt_names       = 'master,master.puppetlabs.vm,puppet,puppet.puppetlabs.vm'
  $group               = 'pe-puppet'
  $logdir              = '/var/log/pe-puppet'
  $modulepath          = '/etc/puppetlabs/puppet/modules:/opt/puppet/share/puppet/modules'
  $rundir              = '/var/run/pe-puppet'
  $section             = 'main'
  $server              = 'master.puppetlabs.vm'
  $user                = 'pe-puppet'
  $vardir              = '/var/opt/lib/pe-puppet'
}
