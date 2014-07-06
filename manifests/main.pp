class puppet::main (
  $archive_file_server = $puppet::params::main::archive_file_server,
  $archive_files       = $puppet::params::main::archive_files,
  $certname            = $puppet::params::main::certname,
  $dns_alt_names       = $puppet::params::main::dns_alt_names,
  $group               = $puppet::params::main::group,
  $logdir              = $puppet::params::main::logdir,
  $modulepath          = $puppet::params::main::modulepath,
  $rundir              = $puppet::params::main::rundir,
  $server              = $puppet::params::main::server,
  $user                = $puppet::params::main::user,
  $vardir              = $puppet::params::main::vardir,
) inherits ::puppet::params::main {
  Ini_setting {
    ensure  => present,
    path    => $config,
    section => $section,
  }
  if $archive_file_server != $::puppet::params::main::archive_file_server {
    ini_setting { 'main archive_file_server':
      setting => 'archive_file_server',
      value   => $archive_file_server,
    }
  }
  if $archive_files != $::puppet::params::main::archive_files {
    ini_setting { 'main archive_files':
      setting => 'archive_files',
      value   => $archive_files,
    }
  }
  if $certname != $::puppet::params::main::certname {
    ini_setting { 'main certname':
      setting => 'certname',
      value   => $certname,
    }
  }
  if $dns_alt_names != $::puppet::params::main::dns_alt_names {
    ini_setting { 'main dns_alt_names':
      setting => 'dns_alt_names',
      value   => $dns_alt_names,
    }
  }
  if $group != $::puppet::params::main::group {
    ini_setting { 'main group':
      setting => 'group',
      value   => $group,
    }
  }
  if $logdir != $::puppet::params::main::logdir {
    ini_setting { 'main logdir':
      setting => 'logdir',
      value   => $logdir,
    }
  }
  if $modulepath != $::puppet::params::main::modulepath {
    ini_setting { 'main modulepath':
      setting => 'modulepath',
      value   => $modulepath,
    }
  }
  if $rundir != $::puppet::params::main::rundir {
    ini_setting { 'main rundir':
      setting => 'rundir',
      value   => $rundir,
    }
  }
  if $server != $::puppet::params::main::server {
    ini_setting { 'main server':
      setting => 'server',
      value   => $server,
    }
  }
  if $user != $::puppet::params::main::user {
    ini_setting { 'main user':
      setting => 'user',
      value   => $user,
    }
  }
  if $vardir != $::puppet::params::main::vardir {
    ini_setting { 'main vardir':
      setting => 'vardir',
      value   => $vardir,
    }
  }
}
