class puppet::agent (
  $agent_catalog_run_lockfile           = $agent_catalog_run_lockfile,
  $agent_disabled_lockfile              = $agent_disabled_lockfile,
  $allow_duplicate_certs                = $allow_duplicate_certs,
  $allow_variables_with_dashes          = $allow_variables_with_dashes,
  $archive_files                        = $archive_files,
  $archive_file_server                  = $archive_file_server,
  $async_storeconfigs                   = $async_storeconfigs,
  $autoflush                            = $autoflush,
  $autosign                             = $autosign,
  $bindaddress                          = $bindaddress,
  $binder                               = $binder,
  $binder_config                        = $binder_config,
  $bucketdir                            = $bucketdir,
  $ca                                   = $ca,
  $cacert                               = $cacert,
  $cacrl                                = $cacrl,
  $cadir                                = $cadir,
  $cakey                                = $cakey,
  $ca_name                              = $ca_name,
  $capass                               = $capass,
  $ca_port                              = $ca_port,
  $caprivatedir                         = $caprivatedir,
  $capub                                = $capub,
  $ca_server                            = $ca_server,
  $catalog_cache_terminus               = $catalog_cache_terminus,
  $catalog_format                       = $catalog_format,
  $catalog_terminus                     = $catalog_terminus,
  $ca_ttl                               = $ca_ttl,
  $certdir                              = $certdir,
  $certdnsnames                         = $certdnsnames,
  $certificate_expire_warning           = $certificate_expire_warning,
  $certificate_revocation               = $certificate_revocation,
  $cert_inventory                       = $cert_inventory,
  $certname                             = $certname,
  $classfile                            = $classfile,
  $clientbucketdir                      = $clientbucketdir,
  $client_datadir                       = $client_datadir,
  $clientyamldir                        = $clientyamldir,
  $code                                 = $code,
  $color                                = $color,
  $confdir                              = $confdir,
  $config                               = $config,
  $config_file_name                     = $config_file_name,
  $configprint                          = $configprint,
  $configtimeout                        = $configtimeout,
  $config_version                       = $config_version,
  $couchdb_url                          = $couchdb_url,
  $csr_attributes                       = $csr_attributes,
  $csrdir                               = $csrdir,
  $daemonize                            = $daemonize,
  $data_binding_terminus                = $data_binding_terminus,
  $dbadapter                            = $dbadapter,
  $dbconnections                        = $dbconnections,
  $dblocation                           = $dblocation,
  $dbmigrate                            = $dbmigrate,
  $dbname                               = $dbname,
  $dbpassword                           = $dbpassword,
  $dbport                               = $dbport,
  $dbserver                             = $dbserver,
  $dbsocket                             = $dbsocket,
  $dbuser                               = $dbuser,
  $default_file_terminus                = $default_file_terminus,
  $default_schedules                    = $default_schedules,
  $deviceconfig                         = $deviceconfig,
  $devicedir                            = $devicedir,
  $diff_args                            = $diff_args,
  $diff                                 = $diff,
  $dns_alt_names                        = $dns_alt_names,
  $document_all                         = $document_all,
  $dynamicfacts                         = $dynamicfacts,
  $environment                          = $environment,
  $evaltrace                            = $evaltrace,
  $external_nodes                       = $external_nodes,
  $factpath                             = $factpath,
  $facts_terminus                       = $facts_terminus,
  $fileserverconfig                     = $fileserverconfig,
  $filetimeout                          = $filetimeout,
  $freeze_main                          = $freeze_main,
  $genmanifest                          = $genmanifest,
  $graphdir                             = $graphdir,
  $graph                                = $graph,
  $group                                = $group,
  $hiera_config                         = $hiera_config,
  $hostcert                             = $hostcert,
  $hostcrl                              = $hostcrl,
  $hostcsr                              = $hostcsr,
  $hostprivkey                          = $hostprivkey,
  $hostpubkey                           = $hostpubkey,
  $http_compression                     = $http_compression,
  $httplog                              = $httplog,
  $http_proxy_host                      = $http_proxy_host,
  $http_proxy_port                      = $http_proxy_port,
  $ignorecache                          = $ignorecache,
  $ignoreimport                         = $ignoreimport,
  $ignoremissingtypes                   = $ignoremissingtypes,
  $ignoreschedules                      = $ignoreschedules,
  $inventory_port                       = $inventory_port,
  $inventory_server                     = $inventory_server,
  $inventory_terminus                   = $inventory_terminus,
  $keylength                            = $keylength,
  $lastrunfile                          = $lastrunfile,
  $lastrunreport                        = $lastrunreport,
  $ldapattrs                            = $ldapattrs,
  $ldapbase                             = $ldapbase,
  $ldapclassattrs                       = $ldapclassattrs,
  $ldapparentattr                       = $ldapparentattr,
  $ldappassword                         = $ldappassword,
  $ldapport                             = $ldapport,
  $ldapserver                           = $ldapserver,
  $ldapssl                              = $ldapssl,
  $ldapstackedattrs                     = $ldapstackedattrs,
  $ldapstring                           = $ldapstring,
  $ldaptls                              = $ldaptls,
  $ldapuser                             = $ldapuser,
  $legacy_query_parameter_serialization = $legacy_query_parameter_serialization,
  $libdir                               = $libdir,
  $listen                               = $listen,
  $localcacert                          = $localcacert,
  $localconfig                          = $localconfig,
  $logdir                               = $logdir,
  $manage_internal_file_permissions     = $manage_internal_file_permissions,
  $manifestdir                          = $manifestdir,
  $manifest                             = $manifest,
  $masterhttplog                        = $masterhttplog,
  $masterlog                            = $masterlog,
  $masterport                           = $masterport,
  $max_deprecations                     = $max_deprecations,
  $max_errors                           = $max_errors,
  $maximum_uid                          = $maximum_uid,
  $max_warnings                         = $max_warnings,
  $mkusers                              = $mkusers,
  $modulepath                           = $modulepath,
  $module_repository                    = $module_repository,
  $module_skeleton_dir                  = $module_skeleton_dir,
  $module_working_dir                   = $module_working_dir,
  $node_cache_terminus                  = $node_cache_terminus,
  $node_name_fact                       = $node_name_fact,
  $node_name                            = $node_name,
  $node_name_value                      = $node_name_value,
  $node_terminus                        = $node_terminus,
  $onetime                              = $onetime,
  $ordering                             = $ordering,
  $parser                               = $parser,
  $passfile                             = $passfile,
  $path                                 = $path,
  $pidfile                              = $pidfile,
  $plugindest                           = $plugindest,
  $pluginfactdest                       = $pluginfactdest,
  $pluginfactsource                     = $pluginfactsource,
  $pluginsignore                        = $pluginsignore,
  $pluginsource                         = $pluginsource,
  $pluginsync                           = $pluginsync,
  $postrun_command                      = $postrun_command,
  $preferred_serialization_format       = $preferred_serialization_format,
  $prerun_command                       = $prerun_command,
  $priority                             = $priority,
  $privatedir                           = $privatedir,
  $privatekeydir                        = $privatekeydir,
  $profile                              = $profile,
  $publickeydir                         = $publickeydir,
  $puppetdlog                           = $puppetdlog,
  $puppetport                           = $puppetport,
  $queue_source                         = $queue_source,
  $queue_type                           = $queue_type,
  $rails_loglevel                       = $rails_loglevel,
  $railslog                             = $railslog,
  $reportdir                            = $reportdir,
  $reportfrom                           = $reportfrom,
  $report_port                          = $report_port,
  $report                               = $report,
  $report_serialization_format          = $report_serialization_format,
  $report_server                        = $report_server,
  $reports                              = $reports,
  $reporturl                            = $reporturl,
  $req_bits                             = $req_bits,
  $requestdir                           = $requestdir,
  $resourcefile                         = $resourcefile,
  $rest_authconfig                      = $rest_authconfig,
  $route_file                           = $route_file,
  $rrddir                               = $rrddir,
  $rrdinterval                          = $rrdinterval,
  $rundir                               = $rundir,
  $runinterval                          = $runinterval,
  $section                              = $section,
  $sendmail                             = $sendmail,
  $serial                               = $serial,
  $server_datadir                       = $server_datadir,
  $server                               = $server,
  $show_diff                            = $show_diff,
  $signeddir                            = $signeddir,
  $smtphelo                             = $smtphelo,
  $smtpport                             = $smtpport,
  $smtpserver                           = $smtpserver,
  $splaylimit                           = $splaylimit,
  $splay                                = $splay,
  $srv_domain                           = $srv_domain,
  $ssl_client_ca_auth                   = $ssl_client_ca_auth,
  $ssl_client_header                    = $ssl_client_header,
  $ssl_client_verify_header             = $ssl_client_verify_header,
  $ssldir                               = $ssldir,
  $ssl_server_ca_auth                   = $ssl_server_ca_auth,
  $statedir                             = $statedir,
  $statefile                            = $statefile,
  $storeconfigs_backend                 = $storeconfigs_backend,
  $storeconfigs                         = $storeconfigs,
  $strict_hostname_checking             = $strict_hostname_checking,
  $stringify_facts                      = $stringify_facts,
  $summarize                            = $summarize,
  $syslogfacility                       = $syslogfacility,
  $tagmap                               = $tagmap,
  $tags                                 = $tags,
  $templatedir                          = $templatedir,
  $thin_storeconfigs                    = $thin_storeconfigs,
  $trace                                = $trace,
  $trusted_node_data                    = $trusted_node_data,
  $use_cached_catalog                   = $use_cached_catalog,
  $usecacheonfailure                    = $usecacheonfailure,
  $user                                 = $user,
  $use_srv_records                      = $use_srv_records,
  $vardir                               = $vardir,
  $waitforcert                          = $waitforcert,
  $yamldir                              = $yamldir,
  $zlib                                 = $zlib,
) inherits ::puppet::params::agent {
  Ini_setting {
    ensure  => present,
    path    => $config,
    section => $section,
  }
  ini_setting { 'agent reports':
    setting => 'reports',
    value   => $reports,
  }
  ini_setting { 'agent classfile':
    setting => 'classfile',
    value   => $classfile,
  }
  ini_setting { 'agent localconfig':
    setting => 'localconfig',
    value   => $localconfig,
  }
  ini_setting { 'agent graph':
    setting => 'graph',
    value   => $graph,
  }
  ini_setting { 'agent pluginsync':
    setting => 'pluginsync',
    value   => $pluginsync,
  }
  ini_setting { 'agent environment':
    setting => 'environment',
    value   => $environment,
  }
  if $confdir != $::puppet::params::agent::confdir {
    ini_setting { 'agent confdir':
      setting => 'confdir',
      value   => $confdir,
    }
  }
  if $vardir != $::puppet::params::agent::vardir {
    ini_setting { 'agent vardir':
      setting => 'vardir',
      value   => $vardir,
    }
  }

  if $section != $::puppet::params::agent::section {
    ini_setting { 'agent section':
      setting => 'name',
      value   => $section,
    }
  }
  if $logdir != $::puppet::params::agent::logdir {
    ini_setting { 'agent logdir':
      setting => 'logdir',
      value   => $logdir,
    }
  }
  if $priority != $::puppet::params::agent::priority {
    ini_setting { 'agent priority':
      setting => 'priority',
      value   => $priority,
    }
  }
  if $trace != $::puppet::params::agent::trace {
    ini_setting { 'agent trace':
      setting => 'trace',
      value   => $trace,
    }
  }
  if $profile != $::puppet::params::agent::profile {
    ini_setting { 'agent profile':
      setting => 'profile',
      value   => $profile,
    }
  }
  if $autoflush != $::puppet::params::agent::autoflush {
    ini_setting { 'agent autoflush':
      setting => 'autoflush',
      value   => $autoflush,
    }
  }
  if $syslogfacility != $::puppet::params::agent::syslogfacility {
    ini_setting { 'agent syslogfacility':
      setting => 'syslogfacility',
      value   => $syslogfacility,
    }
  }
  if $statedir != $::puppet::params::agent::statedir {
    ini_setting { 'agent statedir':
      setting => 'statedir',
      value   => $statedir,
    }
  }
  if $rundir != $::puppet::params::agent::rundir {
    ini_setting { 'agent rundir':
      setting => 'rundir',
      value   => $rundir,
    }
  }
  if $genmanifest != $::puppet::params::agent::genmanifest {
    ini_setting { 'agent genmanifest':
      setting => 'genmanifest',
      value   => $genmanifest,
    }
  }
  if $configprint != $::puppet::params::agent::configprint {
    ini_setting { 'agent configprint':
      setting => 'configprint',
      value   => $configprint,
    }
  }
  if $color != $::puppet::params::agent::color {
    ini_setting { 'agent color':
      setting => 'color',
      value   => $color,
    }
  }
  if $mkusers != $::puppet::params::agent::mkusers {
    ini_setting { 'agent mkusers':
      setting => 'mkusers',
      value   => $mkusers,
    }
  }
  if $manage_internal_file_permissions != $::puppet::params::agent::manage_internal_file_permissions {
    ini_setting { 'agent manage_internal_file_permissions':
      setting => 'manage_internal_file_permissions',
      value   => $manage_internal_file_permissions,
    }
  }
  if $onetime != $::puppet::params::agent::onetime {
    ini_setting { 'agent onetime':
      setting => 'onetime',
      value   => $onetime,
    }
  }
  if $path != $::puppet::params::agent::path {
    ini_setting { 'agent path':
      setting => 'path',
      value   => $path,
    }
  }
  if $libdir != $::puppet::params::agent::libdir {
    ini_setting { 'agent libdir':
      setting => 'libdir',
      value   => $libdir,
    }
  }
  if $ignoreimport != $::puppet::params::agent::ignoreimport {
    ini_setting { 'agent ignoreimport':
      setting => 'ignoreimport',
      value   => $ignoreimport,
    }
  }
  if $diff_args != $::puppet::params::agent::diff_args {
    ini_setting { 'agent diff_args':
      setting => 'diff_args',
      value   => $diff_args,
    }
  }
  if $diff != $::puppet::params::agent::diff {
    ini_setting { 'agent diff':
      setting => 'diff',
      value   => $diff,
    }
  }
  if $show_diff != $::puppet::params::agent::show_diff {
    ini_setting { 'agent show_diff':
      setting => 'show_diff',
      value   => $show_diff,
    }
  }
  if $daemonize != $::puppet::params::agent::daemonize {
    ini_setting { 'agent daemonize':
      setting => 'daemonize',
      value   => $daemonize,
    }
  }
  if $maximum_uid != $::puppet::params::agent::maximum_uid {
    ini_setting { 'agent maximum_uid':
      setting => 'maximum_uid',
      value   => $maximum_uid,
    }
  }
  if $route_file != $::puppet::params::agent::route_file {
    ini_setting { 'agent route_file':
      setting => 'route_file',
      value   => $route_file,
    }
  }
  if $node_terminus != $::puppet::params::agent::node_terminus {
    ini_setting { 'agent node_terminus':
      setting => 'node_terminus',
      value   => $node_terminus,
    }
  }
  if $node_cache_terminus != $::puppet::params::agent::node_cache_terminus {
    ini_setting { 'agent node_cache_terminus':
      setting => 'node_cache_terminus',
      value   => $node_cache_terminus,
    }
  }
  if $data_binding_terminus != $::puppet::params::agent::data_binding_terminus {
    ini_setting { 'agent data_binding_terminus':
      setting => 'data_binding_terminus',
      value   => $data_binding_terminus,
    }
  }
  if $hiera_config != $::puppet::params::agent::hiera_config {
    ini_setting { 'agent hiera_config':
      setting => 'hiera_config',
      value   => $hiera_config,
    }
  }
  if $binder != $::puppet::params::agent::binder {
    ini_setting { 'agent binder':
      setting => 'binder',
      value   => $binder,
    }
  }
  if $binder_config != $::puppet::params::agent::binder_config {
    ini_setting { 'agent binder_config':
      setting => 'binder_config',
      value   => $binder_config,
    }
  }
  if $catalog_terminus != $::puppet::params::agent::catalog_terminus {
    ini_setting { 'agent catalog_terminus':
      setting => 'catalog_terminus',
      value   => $catalog_terminus,
    }
  }
  if $catalog_cache_terminus != $::puppet::params::agent::catalog_cache_terminus {
    ini_setting { 'agent catalog_cache_terminus':
      setting => 'catalog_cache_terminus',
      value   => $catalog_cache_terminus,
    }
  }
  if $facts_terminus != $::puppet::params::agent::facts_terminus {
    ini_setting { 'agent facts_terminus':
      setting => 'facts_terminus',
      value   => $facts_terminus,
    }
  }
  if $inventory_terminus != $::puppet::params::agent::inventory_terminus {
    ini_setting { 'agent inventory_terminus':
      setting => 'inventory_terminus',
      value   => $inventory_terminus,
    }
  }
  if $default_file_terminus != $::puppet::params::agent::default_file_terminus {
    ini_setting { 'agent default_file_terminus':
      setting => 'default_file_terminus',
      value   => $default_file_terminus,
    }
  }
  if $httplog != $::puppet::params::agent::httplog {
    ini_setting { 'agent httplog':
      setting => 'httplog',
      value   => $httplog,
    }
  }
  if $http_proxy_host != $::puppet::params::agent::http_proxy_host {
    ini_setting { 'agent http_proxy_host':
      setting => 'http_proxy_host',
      value   => $http_proxy_host,
    }
  }
  if $http_proxy_port != $::puppet::params::agent::http_proxy_port {
    ini_setting { 'agent http_proxy_port':
      setting => 'http_proxy_port',
      value   => $http_proxy_port,
    }
  }
  if $filetimeout != $::puppet::params::agent::filetimeout {
    ini_setting { 'agent filetimeout':
      setting => 'filetimeout',
      value   => $filetimeout,
    }
  }
  if $queue_type != $::puppet::params::agent::queue_type {
    ini_setting { 'agent queue_type':
      setting => 'queue_type',
      value   => $queue_type,
    }
  }
  if $queue_source != $::puppet::params::agent::queue_source {
    ini_setting { 'agent queue_source':
      setting => 'queue_source',
      value   => $queue_source,
    }
  }
  if $async_storeconfigs != $::puppet::params::agent::async_storeconfigs {
    ini_setting { 'agent async_storeconfigs':
      setting => 'async_storeconfigs',
      value   => $async_storeconfigs,
    }
  }
  if $thin_storeconfigs != $::puppet::params::agent::thin_storeconfigs {
    ini_setting { 'agent thin_storeconfigs':
      setting => 'thin_storeconfigs',
      value   => $thin_storeconfigs,
    }
  }
  if $config_version != $::puppet::params::agent::config_version {
    ini_setting { 'agent config_version':
      setting => 'config_version',
      value   => $config_version,
    }
  }
  if $zlib != $::puppet::params::agent::zlib {
    ini_setting { 'agent zlib':
      setting => 'zlib',
      value   => $zlib,
    }
  }
  if $prerun_command != $::puppet::params::agent::prerun_command {
    ini_setting { 'agent prerun_command':
      setting => 'prerun_command',
      value   => $prerun_command,
    }
  }
  if $postrun_command != $::puppet::params::agent::postrun_command {
    ini_setting { 'agent postrun_command':
      setting => 'postrun_command',
      value   => $postrun_command,
    }
  }
  if $freeze_main != $::puppet::params::agent::freeze_main {
    ini_setting { 'agent freeze_main':
      setting => 'freeze_main',
      value   => $freeze_main,
    }
  }
  if $stringify_facts != $::puppet::params::agent::stringify_facts {
    ini_setting { 'agent stringify_facts':
      setting => 'stringify_facts',
      value   => $stringify_facts,
    }
  }
  if $trusted_node_data != $::puppet::params::agent::trusted_node_data {
    ini_setting { 'agent trusted_node_data':
      setting => 'trusted_node_data',
      value   => $trusted_node_data,
    }
  }
  if $certname != $::puppet::params::agent::certname {
    ini_setting { 'agent certname':
      setting => 'certname',
      value   => $certname,
    }
  }
  if $certdnsnames != $::puppet::params::agent::certdnsnames {
    ini_setting { 'agent certdnsnames':
      setting => 'certdnsnames',
      value   => $certdnsnames,
    }
  }
  if $dns_alt_names != $::puppet::params::agent::dns_alt_names {
    ini_setting { 'agent dns_alt_names':
      setting => 'dns_alt_names',
      value   => $dns_alt_names,
    }
  }
  if $csr_attributes != $::puppet::params::agent::csr_attributes {
    ini_setting { 'agent csr_attributes':
      setting => 'csr_attributes',
      value   => $csr_attributes,
    }
  }
  if $certdir != $::puppet::params::agent::certdir {
    ini_setting { 'agent certdir':
      setting => 'certdir',
      value   => $certdir,
    }
  }
  if $ssldir != $::puppet::params::agent::ssldir {
    ini_setting { 'agent ssldir':
      setting => 'ssldir',
      value   => $ssldir,
    }
  }
  if $publickeydir != $::puppet::params::agent::publickeydir {
    ini_setting { 'agent publickeydir':
      setting => 'publickeydir',
      value   => $publickeydir,
    }
  }
  if $requestdir != $::puppet::params::agent::requestdir {
    ini_setting { 'agent requestdir':
      setting => 'requestdir',
      value   => $requestdir,
    }
  }
  if $privatekeydir != $::puppet::params::agent::privatekeydir {
    ini_setting { 'agent privatekeydir':
      setting => 'privatekeydir',
      value   => $privatekeydir,
    }
  }
  if $privatedir != $::puppet::params::agent::privatedir {
    ini_setting { 'agent privatedir':
      setting => 'privatedir',
      value   => $privatedir,
    }
  }
  if $passfile != $::puppet::params::agent::passfile {
    ini_setting { 'agent passfile':
      setting => 'passfile',
      value   => $passfile,
    }
  }
  if $hostcsr != $::puppet::params::agent::hostcsr {
    ini_setting { 'agent hostcsr':
      setting => 'hostcsr',
      value   => $hostcsr,
    }
  }
  if $hostcert != $::puppet::params::agent::hostcert {
    ini_setting { 'agent hostcert':
      setting => 'hostcert',
      value   => $hostcert,
    }
  }
  if $hostprivkey != $::puppet::params::agent::hostprivkey {
    ini_setting { 'agent hostprivkey':
      setting => 'hostprivkey',
      value   => $hostprivkey,
    }
  }
  if $hostpubkey != $::puppet::params::agent::hostpubkey {
    ini_setting { 'agent hostpubkey':
      setting => 'hostpubkey',
      value   => $hostpubkey,
    }
  }
  if $localcacert != $::puppet::params::agent::localcacert {
    ini_setting { 'agent localcacert':
      setting => 'localcacert',
      value   => $localcacert,
    }
  }
  if $ssl_client_ca_auth != $::puppet::params::agent::ssl_client_ca_auth {
    ini_setting { 'agent ssl_client_ca_auth':
      setting => 'ssl_client_ca_auth',
      value   => $ssl_client_ca_auth,
    }
  }
  if $ssl_server_ca_auth != $::puppet::params::agent::ssl_server_ca_auth {
    ini_setting { 'agent ssl_server_ca_auth':
      setting => 'ssl_server_ca_auth',
      value   => $ssl_server_ca_auth,
    }
  }
  if $hostcrl != $::puppet::params::agent::hostcrl {
    ini_setting { 'agent hostcrl':
      setting => 'hostcrl',
      value   => $hostcrl,
    }
  }
  if $certificate_revocation != $::puppet::params::agent::certificate_revocation {
    ini_setting { 'agent certificate_revocation':
      setting => 'certificate_revocation',
      value   => $certificate_revocation,
    }
  }
  if $certificate_expire_warning != $::puppet::params::agent::certificate_expire_warning {
    ini_setting { 'agent certificate_expire_warning':
      setting => 'certificate_expire_warning',
      value   => $certificate_expire_warning,
    }
  }
  if $plugindest != $::puppet::params::agent::plugindest {
    ini_setting { 'agent plugindest':
      setting => 'plugindest',
      value   => $plugindest,
    }
  }
  if $pluginsource != $::puppet::params::agent::pluginsource {
    ini_setting { 'agent pluginsource':
      setting => 'pluginsource',
      value   => $pluginsource,
    }
  }
  if $pluginfactdest != $::puppet::params::agent::pluginfactdest {
    ini_setting { 'agent pluginfactdest':
      setting => 'pluginfactdest',
      value   => $pluginfactdest,
    }
  }
  if $pluginfactsource != $::puppet::params::agent::pluginfactsource {
    ini_setting { 'agent pluginfactsource':
      setting => 'pluginfactsource',
      value   => $pluginfactsource,
    }
  }
  if $pluginsignore != $::puppet::params::agent::pluginsignore {
    ini_setting { 'agent pluginsignore':
      setting => 'pluginsignore',
      value   => $pluginsignore,
    }
  }
  if $factpath != $::puppet::params::agent::factpath {
    ini_setting { 'agent factpath':
      setting => 'factpath',
      value   => $factpath,
    }
  }
  if $external_nodes != $::puppet::params::agent::external_nodes {
    ini_setting { 'agent external_nodes':
      setting => 'external_nodes',
      value   => $external_nodes,
    }
  }
  if $module_repository != $::puppet::params::agent::module_repository {
    ini_setting { 'agent module_repository':
      setting => 'module_repository',
      value   => $module_repository,
    }
  }
  if $module_working_dir != $::puppet::params::agent::module_working_dir {
    ini_setting { 'agent module_working_dir':
      setting => 'module_working_dir',
      value   => $module_working_dir,
    }
  }
  if $module_skeleton_dir != $::puppet::params::agent::module_skeleton_dir {
    ini_setting { 'agent module_skeleton_dir':
      setting => 'module_skeleton_dir',
      value   => $module_skeleton_dir,
    }
  }
  if $ca_name != $::puppet::params::agent::ca_name {
    ini_setting { 'agent ca_name':
      setting => 'ca_name',
      value   => $ca_name,
    }
  }
  if $cadir != $::puppet::params::agent::cadir {
    ini_setting { 'agent cadir':
      setting => 'cadir',
      value   => $cadir,
    }
  }
  if $cacert != $::puppet::params::agent::cacert {
    ini_setting { 'agent cacert':
      setting => 'cacert',
      value   => $cacert,
    }
  }
  if $cakey != $::puppet::params::agent::cakey {
    ini_setting { 'agent cakey':
      setting => 'cakey',
      value   => $cakey,
    }
  }
  if $capub != $::puppet::params::agent::capub {
    ini_setting { 'agent capub':
      setting => 'capub',
      value   => $capub,
    }
  }
  if $cacrl != $::puppet::params::agent::cacrl {
    ini_setting { 'agent cacrl':
      setting => 'cacrl',
      value   => $cacrl,
    }
  }
  if $caprivatedir != $::puppet::params::agent::caprivatedir {
    ini_setting { 'agent caprivatedir':
      setting => 'caprivatedir',
      value   => $caprivatedir,
    }
  }
  if $csrdir != $::puppet::params::agent::csrdir {
    ini_setting { 'agent csrdir':
      setting => 'csrdir',
      value   => $csrdir,
    }
  }
  if $signeddir != $::puppet::params::agent::signeddir {
    ini_setting { 'agent signeddir':
      setting => 'signeddir',
      value   => $signeddir,
    }
  }
  if $capass != $::puppet::params::agent::capass {
    ini_setting { 'agent capass':
      setting => 'capass',
      value   => $capass,
    }
  }
  if $serial != $::puppet::params::agent::serial {
    ini_setting { 'agent serial':
      setting => 'serial',
      value   => $serial,
    }
  }
  if $autosign != $::puppet::params::agent::autosign {
    ini_setting { 'agent autosign':
      setting => 'autosign',
      value   => $autosign,
    }
  }
  if $allow_duplicate_certs != $::puppet::params::agent::allow_duplicate_certs {
    ini_setting { 'agent allow_duplicate_certs':
      setting => 'allow_duplicate_certs',
      value   => $allow_duplicate_certs,
    }
  }
  if $ca_ttl != $::puppet::params::agent::ca_ttl {
    ini_setting { 'agent ca_ttl':
      setting => 'ca_ttl',
      value   => $ca_ttl,
    }
  }
  if $req_bits != $::puppet::params::agent::req_bits {
    ini_setting { 'agent req_bits':
      setting => 'req_bits',
      value   => $req_bits,
    }
  }
  if $keylength != $::puppet::params::agent::keylength {
    ini_setting { 'agent keylength':
      setting => 'keylength',
      value   => $keylength,
    }
  }
  if $cert_inventory != $::puppet::params::agent::cert_inventory {
    ini_setting { 'agent cert_inventory':
      setting => 'cert_inventory',
      value   => $cert_inventory,
    }
  }
  if $config_file_name != $::puppet::params::agent::config_file_name {
    ini_setting { 'agent config_file_name':
      setting => 'config_file_name',
      value   => $config_file_name,
    }
  }
  if $config != $::puppet::params::agent::config {
    ini_setting { 'agent config':
      setting => 'config',
      value   => $config,
    }
  }
  if $pidfile != $::puppet::params::agent::pidfile {
    ini_setting { 'agent pidfile':
      setting => 'pidfile',
      value   => $pidfile,
    }
  }
  if $bindaddress != $::puppet::params::agent::bindaddress {
    ini_setting { 'agent bindaddress':
      setting => 'bindaddress',
      value   => $bindaddress,
    }
  }
  if $user != $::puppet::params::agent::user {
    ini_setting { 'agent user':
      setting => 'user',
      value   => $user,
    }
  }
  if $group != $::puppet::params::agent::group {
    ini_setting { 'agent group':
      setting => 'group',
      value   => $group,
    }
  }
  if $manifestdir != $::puppet::params::agent::manifestdir {
    ini_setting { 'agent manifestdir':
      setting => 'manifestdir',
      value   => $manifestdir,
    }
  }
  if $manifest != $::puppet::params::agent::manifest {
    ini_setting { 'agent manifest':
      setting => 'manifest',
      value   => $manifest,
    }
  }
  if $code != $::puppet::params::agent::code {
    ini_setting { 'agent code':
      setting => 'code',
      value   => $code,
    }
  }
  if $masterlog != $::puppet::params::agent::masterlog {
    ini_setting { 'agent masterlog':
      setting => 'masterlog',
      value   => $masterlog,
    }
  }
  if $masterhttplog != $::puppet::params::agent::masterhttplog {
    ini_setting { 'agent masterhttplog':
      setting => 'masterhttplog',
      value   => $masterhttplog,
    }
  }
  if $masterport != $::puppet::params::agent::masterport {
    ini_setting { 'agent masterport':
      setting => 'masterport',
      value   => $masterport,
    }
  }
  if $node_name != $::puppet::params::agent::node_name {
    ini_setting { 'agent node_name':
      setting => 'node_name',
      value   => $node_name,
    }
  }
  if $bucketdir != $::puppet::params::agent::bucketdir {
    ini_setting { 'agent bucketdir':
      setting => 'bucketdir',
      value   => $bucketdir,
    }
  }
  if $rest_authconfig != $::puppet::params::agent::rest_authconfig {
    ini_setting { 'agent rest_authconfig':
      setting => 'rest_authconfig',
      value   => $rest_authconfig,
    }
  }
  if $ca != $::puppet::params::agent::ca {
    ini_setting { 'agent ca':
      setting => 'ca',
      value   => $ca,
    }
  }
  if $modulepath != $::puppet::params::agent::modulepath {
    ini_setting { 'agent modulepath':
      setting => 'modulepath',
      value   => $modulepath,
    }
  }
  if $ssl_client_header != $::puppet::params::agent::ssl_client_header {
    ini_setting { 'agent ssl_client_header':
      setting => 'ssl_client_header',
      value   => $ssl_client_header,
    }
  }
  if $ssl_client_verify_header != $::puppet::params::agent::ssl_client_verify_header {
    ini_setting { 'agent ssl_client_verify_header':
      setting => 'ssl_client_verify_header',
      value   => $ssl_client_verify_header,
    }
  }
  if $yamldir != $::puppet::params::agent::yamldir {
    ini_setting { 'agent yamldir':
      setting => 'yamldir',
      value   => $yamldir,
    }
  }
  if $server_datadir != $::puppet::params::agent::server_datadir {
    ini_setting { 'agent server_datadir':
      setting => 'server_datadir',
      value   => $server_datadir,
    }
  }
  if $reportdir != $::puppet::params::agent::reportdir {
    ini_setting { 'agent reportdir':
      setting => 'reportdir',
      value   => $reportdir,
    }
  }
  if $reporturl != $::puppet::params::agent::reporturl {
    ini_setting { 'agent reporturl':
      setting => 'reporturl',
      value   => $reporturl,
    }
  }
  if $fileserverconfig != $::puppet::params::agent::fileserverconfig {
    ini_setting { 'agent fileserverconfig':
      setting => 'fileserverconfig',
      value   => $fileserverconfig,
    }
  }
  if $strict_hostname_checking != $::puppet::params::agent::strict_hostname_checking {
    ini_setting { 'agent strict_hostname_checking':
      setting => 'strict_hostname_checking',
      value   => $strict_hostname_checking,
    }
  }
  if $storeconfigs != $::puppet::params::agent::storeconfigs {
    ini_setting { 'agent storeconfigs':
      setting => 'storeconfigs',
      value   => $storeconfigs,
    }
  }
  if $storeconfigs_backend != $::puppet::params::agent::storeconfigs_backend {
    ini_setting { 'agent storeconfigs_backend':
      setting => 'storeconfigs_backend',
      value   => $storeconfigs_backend,
    }
  }
  if $rrddir != $::puppet::params::agent::rrddir {
    ini_setting { 'agent rrddir':
      setting => 'rrddir',
      value   => $rrddir,
    }
  }
  if $rrdinterval != $::puppet::params::agent::rrdinterval {
    ini_setting { 'agent rrdinterval':
      setting => 'rrdinterval',
      value   => $rrdinterval,
    }
  }
  if $devicedir != $::puppet::params::agent::devicedir {
    ini_setting { 'agent devicedir':
      setting => 'devicedir',
      value   => $devicedir,
    }
  }
  if $deviceconfig != $::puppet::params::agent::deviceconfig {
    ini_setting { 'agent deviceconfig':
      setting => 'deviceconfig',
      value   => $deviceconfig,
    }
  }
  if $node_name_value != $::puppet::params::agent::node_name_value {
    ini_setting { 'agent node_name_value':
      setting => 'node_name_value',
      value   => $node_name_value,
    }
  }
  if $node_name_fact != $::puppet::params::agent::node_name_fact {
    ini_setting { 'agent node_name_fact':
      setting => 'node_name_fact',
      value   => $node_name_fact,
    }
  }
  if $statefile != $::puppet::params::agent::statefile {
    ini_setting { 'agent statefile':
      setting => 'statefile',
      value   => $statefile,
    }
  }
  if $clientyamldir != $::puppet::params::agent::clientyamldir {
    ini_setting { 'agent clientyamldir':
      setting => 'clientyamldir',
      value   => $clientyamldir,
    }
  }
  if $client_datadir != $::puppet::params::agent::client_datadir {
    ini_setting { 'agent client_datadir':
      setting => 'client_datadir',
      value   => $client_datadir,
    }
  }
  if $resourcefile != $::puppet::params::agent::resourcefile {
    ini_setting { 'agent resourcefile':
      setting => 'resourcefile',
      value   => $resourcefile,
    }
  }
  if $puppetdlog != $::puppet::params::agent::puppetdlog {
    ini_setting { 'agent puppetdlog':
      setting => 'puppetdlog',
      value   => $puppetdlog,
    }
  }
  if $server != $::puppet::params::agent::server {
    ini_setting { 'agent server':
      setting => 'server',
      value   => $server,
    }
  }
  if $use_srv_records != $::puppet::params::agent::use_srv_records {
    ini_setting { 'agent use_srv_records':
      setting => 'use_srv_records',
      value   => $use_srv_records,
    }
  }
  if $srv_domain != $::puppet::params::agent::srv_domain {
    ini_setting { 'agent srv_domain':
      setting => 'srv_domain',
      value   => $srv_domain,
    }
  }
  if $ignoreschedules != $::puppet::params::agent::ignoreschedules {
    ini_setting { 'agent ignoreschedules':
      setting => 'ignoreschedules',
      value   => $ignoreschedules,
    }
  }
  if $default_schedules != $::puppet::params::agent::default_schedules {
    ini_setting { 'agent default_schedules':
      setting => 'default_schedules',
      value   => $default_schedules,
    }
  }
  if $puppetport != $::puppet::params::agent::puppetport {
    ini_setting { 'agent puppetport':
      setting => 'puppetport',
      value   => $puppetport,
    }
  }
  if $runinterval != $::puppet::params::agent::runinterval {
    ini_setting { 'agent runinterval':
      setting => 'runinterval',
      value   => $runinterval,
    }
  }
  if $listen != $::puppet::params::agent::listen {
    ini_setting { 'agent listen':
      setting => 'listen',
      value   => $listen,
    }
  }
  if $ca_server != $::puppet::params::agent::ca_server {
    ini_setting { 'agent ca_server':
      setting => 'ca_server',
      value   => $ca_server,
    }
  }
  if $ca_port != $::puppet::params::agent::ca_port {
    ini_setting { 'agent ca_port':
      setting => 'ca_port',
      value   => $ca_port,
    }
  }
  if $catalog_format != $::puppet::params::agent::catalog_format {
    ini_setting { 'agent catalog_format':
      setting => 'catalog_format',
      value   => $catalog_format,
    }
  }
  if $preferred_serialization_format != $::puppet::params::agent::preferred_serialization_format {
    ini_setting { 'agent preferred_serialization_format':
      setting => 'preferred_serialization_format',
      value   => $preferred_serialization_format,
    }
  }
  if $report_serialization_format != $::puppet::params::agent::report_serialization_format {
    ini_setting { 'agent report_serialization_format':
      setting => 'report_serialization_format',
      value   => $report_serialization_format,
    }
  }
  if $legacy_query_parameter_serialization != $::puppet::params::agent::legacy_query_parameter_serialization {
    ini_setting { 'agent legacy_query_parameter_serialization':
      setting => 'legacy_query_parameter_serialization',
      value   => $legacy_query_parameter_serialization,
    }
  }
  if $agent_catalog_run_lockfile != $::puppet::params::agent::agent_catalog_run_lockfile {
    ini_setting { 'agent agent_catalog_run_lockfile':
      setting => 'agent_catalog_run_lockfile',
      value   => $agent_catalog_run_lockfile,
    }
  }
  if $agent_disabled_lockfile != $::puppet::params::agent::agent_disabled_lockfile {
    ini_setting { 'agent agent_disabled_lockfile':
      setting => 'agent_disabled_lockfile',
      value   => $agent_disabled_lockfile,
    }
  }
  if $usecacheonfailure != $::puppet::params::agent::usecacheonfailure {
    ini_setting { 'agent usecacheonfailure':
      setting => 'usecacheonfailure',
      value   => $usecacheonfailure,
    }
  }
  if $use_cached_catalog != $::puppet::params::agent::use_cached_catalog {
    ini_setting { 'agent use_cached_catalog':
      setting => 'use_cached_catalog',
      value   => $use_cached_catalog,
    }
  }
  if $ignoremissingtypes != $::puppet::params::agent::ignoremissingtypes {
    ini_setting { 'agent ignoremissingtypes':
      setting => 'ignoremissingtypes',
      value   => $ignoremissingtypes,
    }
  }
  if $ignorecache != $::puppet::params::agent::ignorecache {
    ini_setting { 'agent ignorecache':
      setting => 'ignorecache',
      value   => $ignorecache,
    }
  }
  if $dynamicfacts != $::puppet::params::agent::dynamicfacts {
    ini_setting { 'agent dynamicfacts':
      setting => 'dynamicfacts',
      value   => $dynamicfacts,
    }
  }
  if $splaylimit != $::puppet::params::agent::splaylimit {
    ini_setting { 'agent splaylimit':
      setting => 'splaylimit',
      value   => $splaylimit,
    }
  }
  if $splay != $::puppet::params::agent::splay {
    ini_setting { 'agent splay':
      setting => 'splay',
      value   => $splay,
    }
  }
  if $clientbucketdir != $::puppet::params::agent::clientbucketdir {
    ini_setting { 'agent clientbucketdir':
      setting => 'clientbucketdir',
      value   => $clientbucketdir,
    }
  }
  if $configtimeout != $::puppet::params::agent::configtimeout {
    ini_setting { 'agent configtimeout':
      setting => 'configtimeout',
      value   => $configtimeout,
    }
  }
  if $report_server != $::puppet::params::agent::report_server {
    ini_setting { 'agent report_server':
      setting => 'report_server',
      value   => $report_server,
    }
  }
  if $report_port != $::puppet::params::agent::report_port {
    ini_setting { 'agent report_port':
      setting => 'report_port',
      value   => $report_port,
    }
  }
  if $inventory_server != $::puppet::params::agent::inventory_server {
    ini_setting { 'agent inventory_server':
      setting => 'inventory_server',
      value   => $inventory_server,
    }
  }
  if $inventory_port != $::puppet::params::agent::inventory_port {
    ini_setting { 'agent inventory_port':
      setting => 'inventory_port',
      value   => $inventory_port,
    }
  }
  if $report != $::puppet::params::agent::report {
    ini_setting { 'agent report':
      setting => 'report',
      value   => $report,
    }
  }
  if $lastrunfile != $::puppet::params::agent::lastrunfile {
    ini_setting { 'agent lastrunfile':
      setting => 'lastrunfile',
      value   => $lastrunfile,
    }
  }
  if $lastrunreport != $::puppet::params::agent::lastrunreport {
    ini_setting { 'agent lastrunreport':
      setting => 'lastrunreport',
      value   => $lastrunreport,
    }
  }
  if $graphdir != $::puppet::params::agent::graphdir {
    ini_setting { 'agent graphdir':
      setting => 'graphdir',
      value   => $graphdir,
    }
  }
  if $http_compression != $::puppet::params::agent::http_compression {
    ini_setting { 'agent http_compression':
      setting => 'http_compression',
      value   => $http_compression,
    }
  }
  if $waitforcert != $::puppet::params::agent::waitforcert {
    ini_setting { 'agent waitforcert':
      setting => 'waitforcert',
      value   => $waitforcert,
    }
  }
  if $ordering != $::puppet::params::agent::ordering {
    ini_setting { 'agent ordering':
      setting => 'ordering',
      value   => $ordering,
    }
  }
  if $archive_files != $::puppet::params::agent::archive_files {
    ini_setting { 'agent archive_files':
      setting => 'archive_files',
      value   => $archive_files,
    }
  }
  if $archive_file_server != $::puppet::params::agent::archive_file_server {
    ini_setting { 'agent archive_file_server':
      setting => 'archive_file_server',
      value   => $archive_file_server,
    }
  }
  if $tagmap != $::puppet::params::agent::tagmap {
    ini_setting { 'agent tagmap':
      setting => 'tagmap',
      value   => $tagmap,
    }
  }
  if $sendmail != $::puppet::params::agent::sendmail {
    ini_setting { 'agent sendmail':
      setting => 'sendmail',
      value   => $sendmail,
    }
  }
  if $reportfrom != $::puppet::params::agent::reportfrom {
    ini_setting { 'agent reportfrom':
      setting => 'reportfrom',
      value   => $reportfrom,
    }
  }
  if $smtpserver != $::puppet::params::agent::smtpserver {
    ini_setting { 'agent smtpserver':
      setting => 'smtpserver',
      value   => $smtpserver,
    }
  }
  if $smtpport != $::puppet::params::agent::smtpport {
    ini_setting { 'agent smtpport':
      setting => 'smtpport',
      value   => $smtpport,
    }
  }
  if $smtphelo != $::puppet::params::agent::smtphelo {
    ini_setting { 'agent smtphelo':
      setting => 'smtphelo',
      value   => $smtphelo,
    }
  }
  if $dblocation != $::puppet::params::agent::dblocation {
    ini_setting { 'agent dblocation':
      setting => 'dblocation',
      value   => $dblocation,
    }
  }
  if $dbadapter != $::puppet::params::agent::dbadapter {
    ini_setting { 'agent dbadapter':
      setting => 'dbadapter',
      value   => $dbadapter,
    }
  }
  if $dbmigrate != $::puppet::params::agent::dbmigrate {
    ini_setting { 'agent dbmigrate':
      setting => 'dbmigrate',
      value   => $dbmigrate,
    }
  }
  if $dbname != $::puppet::params::agent::dbname {
    ini_setting { 'agent dbname':
      setting => 'dbname',
      value   => $dbname,
    }
  }
  if $dbserver != $::puppet::params::agent::dbserver {
    ini_setting { 'agent dbserver':
      setting => 'dbserver',
      value   => $dbserver,
    }
  }
  if $dbport != $::puppet::params::agent::dbport {
    ini_setting { 'agent dbport':
      setting => 'dbport',
      value   => $dbport,
    }
  }
  if $dbuser != $::puppet::params::agent::dbuser {
    ini_setting { 'agent dbuser':
      setting => 'dbuser',
      value   => $dbuser,
    }
  }
  if $dbpassword != $::puppet::params::agent::dbpassword {
    ini_setting { 'agent dbpassword':
      setting => 'dbpassword',
      value   => $dbpassword,
    }
  }
  if $dbconnections != $::puppet::params::agent::dbconnections {
    ini_setting { 'agent dbconnections':
      setting => 'dbconnections',
      value   => $dbconnections,
    }
  }
  if $dbsocket != $::puppet::params::agent::dbsocket {
    ini_setting { 'agent dbsocket':
      setting => 'dbsocket',
      value   => $dbsocket,
    }
  }
  if $railslog != $::puppet::params::agent::railslog {
    ini_setting { 'agent railslog':
      setting => 'railslog',
      value   => $railslog,
    }
  }
  if $rails_loglevel != $::puppet::params::agent::rails_loglevel {
    ini_setting { 'agent rails_loglevel':
      setting => 'rails_loglevel',
      value   => $rails_loglevel,
    }
  }
  if $couchdb_url != $::puppet::params::agent::couchdb_url {
    ini_setting { 'agent couchdb_url':
      setting => 'couchdb_url',
      value   => $couchdb_url,
    }
  }
  if $tags != $::puppet::params::agent::tags {
    ini_setting { 'agent tags':
      setting => 'tags',
      value   => $tags,
    }
  }
  if $evaltrace != $::puppet::params::agent::evaltrace {
    ini_setting { 'agent evaltrace':
      setting => 'evaltrace',
      value   => $evaltrace,
    }
  }
  if $summarize != $::puppet::params::agent::summarize {
    ini_setting { 'agent summarize':
      setting => 'summarize',
      value   => $summarize,
    }
  }
  if $ldapssl != $::puppet::params::agent::ldapssl {
    ini_setting { 'agent ldapssl':
      setting => 'ldapssl',
      value   => $ldapssl,
    }
  }
  if $ldaptls != $::puppet::params::agent::ldaptls {
    ini_setting { 'agent ldaptls':
      setting => 'ldaptls',
      value   => $ldaptls,
    }
  }
  if $ldapserver != $::puppet::params::agent::ldapserver {
    ini_setting { 'agent ldapserver':
      setting => 'ldapserver',
      value   => $ldapserver,
    }
  }
  if $ldapport != $::puppet::params::agent::ldapport {
    ini_setting { 'agent ldapport':
      setting => 'ldapport',
      value   => $ldapport,
    }
  }
  if $ldapstring != $::puppet::params::agent::ldapstring {
    ini_setting { 'agent ldapstring':
      setting => 'ldapstring',
      value   => $ldapstring,
    }
  }
  if $ldapclassattrs != $::puppet::params::agent::ldapclassattrs {
    ini_setting { 'agent ldapclassattrs':
      setting => 'ldapclassattrs',
      value   => $ldapclassattrs,
    }
  }
  if $ldapstackedattrs != $::puppet::params::agent::ldapstackedattrs {
    ini_setting { 'agent ldapstackedattrs':
      setting => 'ldapstackedattrs',
      value   => $ldapstackedattrs,
    }
  }
  if $ldapattrs != $::puppet::params::agent::ldapattrs {
    ini_setting { 'agent ldapattrs':
      setting => 'ldapattrs',
      value   => $ldapattrs,
    }
  }
  if $ldapparentattr != $::puppet::params::agent::ldapparentattr {
    ini_setting { 'agent ldapparentattr':
      setting => 'ldapparentattr',
      value   => $ldapparentattr,
    }
  }
  if $ldapuser != $::puppet::params::agent::ldapuser {
    ini_setting { 'agent ldapuser':
      setting => 'ldapuser',
      value   => $ldapuser,
    }
  }
  if $ldappassword != $::puppet::params::agent::ldappassword {
    ini_setting { 'agent ldappassword':
      setting => 'ldappassword',
      value   => $ldappassword,
    }
  }
  if $ldapbase != $::puppet::params::agent::ldapbase {
    ini_setting { 'agent ldapbase':
      setting => 'ldapbase',
      value   => $ldapbase,
    }
  }
  if $templatedir != $::puppet::params::agent::templatedir {
    ini_setting { 'agent templatedir':
      setting => 'templatedir',
      value   => $templatedir,
    }
  }
  if $allow_variables_with_dashes != $::puppet::params::agent::allow_variables_with_dashes {
    ini_setting { 'agent allow_variables_with_dashes':
      setting => 'allow_variables_with_dashes',
      value   => $allow_variables_with_dashes,
    }
  }
  if $parser != $::puppet::params::agent::parser {
    ini_setting { 'agent parser':
      setting => 'parser',
      value   => $parser,
    }
  }
  if $max_errors != $::puppet::params::agent::max_errors {
    ini_setting { 'agent max_errors':
      setting => 'max_errors',
      value   => $max_errors,
    }
  }
  if $max_warnings != $::puppet::params::agent::max_warnings {
    ini_setting { 'agent max_warnings':
      setting => 'max_warnings',
      value   => $max_warnings,
    }
  }
  if $max_deprecations != $::puppet::params::agent::max_deprecations {
    ini_setting { 'agent max_deprecations':
      setting => 'max_deprecations',
      value   => $max_deprecations,
    }
  }
  if $document_all != $::puppet::params::agent::document_all {
    ini_setting { 'agent document_all':
      setting => 'document_all',
      value   => $document_all,
    }
  }
}
