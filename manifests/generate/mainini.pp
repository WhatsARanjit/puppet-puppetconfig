class puppet::generate::mainini (
  $req = {
    archive_file_server => $puppet::params::main::archive_file_server,
    archive_files       => $puppet::params::main::archive_files,
    certname            => $puppet::params::main::certname,
    config              => $puppet::params::main::config,
    dns_alt_names       => $puppet::params::main::dns_alt_names,
    group               => $puppet::params::main::group,
    logdir              => $puppet::params::main::logdir,
    modulepath          => $puppet::params::main::modulepath,
    rundir              => $puppet::params::main::rundir,
    section             => $puppet::params::main::section,
    server              => $puppet::params::main::server,
    user                => $puppet::params::main::user,
    vardir              => $puppet::params::main::vardir,
  },
  $ini = {}
) inherits ::puppet::params::main {
  file { '/tmp/mainini.txt':
    ensure  => present,
    content => template('puppet/ini_generator.erb'),
  }
}
