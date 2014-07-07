class puppetconfig::generate::mainini (
  $req = {
    archive_file_server => $puppetconfig::params::main::archive_file_server,
    archive_files       => $puppetconfig::params::main::archive_files,
    certname            => $puppetconfig::params::main::certname,
    config              => $puppetconfig::params::main::config,
    dns_alt_names       => $puppetconfig::params::main::dns_alt_names,
    group               => $puppetconfig::params::main::group,
    logdir              => $puppetconfig::params::main::logdir,
    modulepath          => $puppetconfig::params::main::modulepath,
    rundir              => $puppetconfig::params::main::rundir,
    section             => $puppetconfig::params::main::section,
    server              => $puppetconfig::params::main::server,
    user                => $puppetconfig::params::main::user,
    vardir              => $puppetconfig::params::main::vardir,
  },
  $ini = {}
) inherits ::puppetconfig::params::main {
  file { '/tmp/mainini.txt':
    ensure  => present,
    content => template('puppet/ini_generator.erb'),
  }
}
