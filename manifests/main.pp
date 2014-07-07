class puppetconfig::main (
  $archive_file_server = $puppetconfig::params::main::archive_file_server,
  $archive_files       = $puppetconfig::params::main::archive_files,
  $certname            = $puppetconfig::params::main::certname,
  $config              = $puppetconfig::params::main::config,
  $dns_alt_names       = $puppetconfig::params::main::dns_alt_names,
  $group               = $puppetconfig::params::main::group,
  $logdir              = $puppetconfig::params::main::logdir,
  $modulepath          = $puppetconfig::params::main::modulepath,
  $rundir              = $puppetconfig::params::main::rundir,
  $section             = $puppetconfig::params::main::section,
  $server              = $puppetconfig::params::main::server,
  $user                = $puppetconfig::params::main::user,
  $vardir              = $puppetconfig::params::main::vardir,
) inherits ::puppetconfig::params::main {
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
