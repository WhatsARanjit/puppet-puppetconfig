class puppet::main (
  $archive_file_server = $puppet::params::main::archive_file_server,
  $archive_files       = $puppet::params::main::archive_files,
  $certname            = $puppet::params::main::certname,
  $config              = $puppet::params::main::config,
  $dns_alt_names       = $puppet::params::main::dns_alt_names,
  $group               = $puppet::params::main::group,
  $logdir              = $puppet::params::main::logdir,
  $modulepath          = $puppet::params::main::modulepath,
  $rundir              = $puppet::params::main::rundir,
  $section             = $puppet::params::main::section,
  $server              = $puppet::params::main::server,
  $user                = $puppet::params::main::user,
  $vardir              = $puppet::params::main::vardir,
) inherits ::puppet::params::main {
  Ini_setting {
    ensure  => present,
    path    => $config,
    section => $section,
  }
  ini_setting { 'main archive_file_server':
    setting => 'archive_file_server',
    value   => $archive_file_server,
  }
  ini_setting { 'main archive_files':
    setting => 'archive_files',
    value   => $archive_files,
  }
  ini_setting { 'main certname':
    setting => 'certname',
    value   => $certname,
  }
  ini_setting { 'main config':
    setting => 'config',
    value   => $config,
  }
  ini_setting { 'main dns_alt_names':
    setting => 'dns_alt_names',
    value   => $dns_alt_names,
  }
  ini_setting { 'main group':
    setting => 'group',
    value   => $group,
  }
  ini_setting { 'main logdir':
    setting => 'logdir',
    value   => $logdir,
  }
  ini_setting { 'main modulepath':
    setting => 'modulepath',
    value   => $modulepath,
  }
  ini_setting { 'main rundir':
    setting => 'rundir',
    value   => $rundir,
  }
  ini_setting { 'main server':
    setting => 'server',
    value   => $server,
  }
  ini_setting { 'main user':
    setting => 'user',
    value   => $user,
  }
  ini_setting { 'main vardir':
    setting => 'vardir',
    value   => $vardir,
  }
}
