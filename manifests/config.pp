define puppetconfig::config (
  $config = $::puppetconfig::main::config,
  $ensure = 'present',
  $section,
  $setting = $title,
  $value
) {
  ini_setting { "${section} ${setting}":
    ensure  => $ensure,
    path    => $config,
    section => $section,
    setting => $setting,
    value   => $value,
  }
}
