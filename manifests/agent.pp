class puppetconfig::agent (
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
) inherits ::puppetconfig::params::agent {
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
  if $confdir != $::puppetconfig::params::agent::confdir {
    ini_setting { 'agent confdir':
      setting => 'confdir',
      value   => $confdir,
    }
  }
  if $vardir != $::puppetconfig::params::agent::vardir {
    ini_setting { 'agent vardir':
      setting => 'vardir',
      value   => $vardir,
    }
  }

  if $section != $::puppetconfig::params::agent::section {
    ini_setting { 'agent section':
      setting => 'name',
      value   => $section,
    }
  }
  if $logdir != $::puppetconfig::params::agent::logdir {
    ini_setting { 'agent logdir':
      setting => 'logdir',
      value   => $logdir,
    }
  }
  if $priority != $::puppetconfig::params::agent::priority {
    ini_setting { 'agent priority':
      setting => 'priority',
      value   => $priority,
    }
  }
  if $trace != $::puppetconfig::params::agent::trace {
    ini_setting { 'agent trace':
      setting => 'trace',
      value   => $trace,
    }
  }
  if $profile != $::puppetconfig::params::agent::profile {
    ini_setting { 'agent profile':
      setting => 'profile',
      value   => $profile,
    }
  }
  if $autoflush != $::puppetconfig::params::agent::autoflush {
    ini_setting { 'agent autoflush':
      setting => 'autoflush',
      value   => $autoflush,
    }
  }
  if $syslogfacility != $::puppetconfig::params::agent::syslogfacility {
    ini_setting { 'agent syslogfacility':
      setting => 'syslogfacility',
      value   => $syslogfacility,
    }
  }
  if $statedir != $::puppetconfig::params::agent::statedir {
    ini_setting { 'agent statedir':
      setting => 'statedir',
      value   => $statedir,
    }
  }
  if $rundir != $::puppetconfig::params::agent::rundir {
    ini_setting { 'agent rundir':
      setting => 'rundir',
      value   => $rundir,
    }
  }
  if $genmanifest != $::puppetconfig::params::agent::genmanifest {
    ini_setting { 'agent genmanifest':
      setting => 'genmanifest',
      value   => $genmanifest,
    }
  }
  if $configprint != $::puppetconfig::params::agent::configprint {
    ini_setting { 'agent configprint':
      setting => 'configprint',
      value   => $configprint,
    }
  }
  if $color != $::puppetconfig::params::agent::color {
    ini_setting { 'agent color':
      setting => 'color',
      value   => $color,
    }
  }
  if $mkusers != $::puppetconfig::params::agent::mkusers {
    ini_setting { 'agent mkusers':
      setting => 'mkusers',
      value   => $mkusers,
    }
  }
  if $manage_internal_file_permissions != $::puppetconfig::params::agent::manage_internal_file_permissions {
    ini_setting { 'agent manage_internal_file_permissions':
      setting => 'manage_internal_file_permissions',
      value   => $manage_internal_file_permissions,
    }
  }
  if $onetime != $::puppetconfig::params::agent::onetime {
    ini_setting { 'agent onetime':
      setting => 'onetime',
      value   => $onetime,
    }
  }
  if $path != $::puppetconfig::params::agent::path {
    ini_setting { 'agent path':
      setting => 'path',
      value   => $path,
    }
  }
  if $libdir != $::puppetconfig::params::agent::libdir {
    ini_setting { 'agent libdir':
      setting => 'libdir',
      value   => $libdir,
    }
  }
  if $ignoreimport != $::puppetconfig::params::agent::ignoreimport {
    ini_setting { 'agent ignoreimport':
      setting => 'ignoreimport',
      value   => $ignoreimport,
    }
  }
  if $diff_args != $::puppetconfig::params::agent::diff_args {
    ini_setting { 'agent diff_args':
      setting => 'diff_args',
      value   => $diff_args,
    }
  }
  if $diff != $::puppetconfig::params::agent::diff {
    ini_setting { 'agent diff':
      setting => 'diff',
      value   => $diff,
    }
  }
  if $show_diff != $::puppetconfig::params::agent::show_diff {
    ini_setting { 'agent show_diff':
      setting => 'show_diff',
      value   => $show_diff,
    }
  }
  if $daemonize != $::puppetconfig::params::agent::daemonize {
    ini_setting { 'agent daemonize':
      setting => 'daemonize',
      value   => $daemonize,
    }
  }
  if $maximum_uid != $::puppetconfig::params::agent::maximum_uid {
    ini_setting { 'agent maximum_uid':
      setting => 'maximum_uid',
      value   => $maximum_uid,
    }
  }
  if $route_file != $::puppetconfig::params::agent::route_file {
    ini_setting { 'agent route_file':
      setting => 'route_file',
      value   => $route_file,
    }
  }
  if $node_terminus != $::puppetconfig::params::agent::node_terminus {
    ini_setting { 'agent node_terminus':
      setting => 'node_terminus',
      value   => $node_terminus,
    }
  }
  if $node_cache_terminus != $::puppetconfig::params::agent::node_cache_terminus {
    ini_setting { 'agent node_cache_terminus':
      setting => 'node_cache_terminus',
      value   => $node_cache_terminus,
    }
  }
  if $data_binding_terminus != $::puppetconfig::params::agent::data_binding_terminus {
    ini_setting { 'agent data_binding_terminus':
      setting => 'data_binding_terminus',
      value   => $data_binding_terminus,
    }
  }
  if $hiera_config != $::puppetconfig::params::agent::hiera_config {
    ini_setting { 'agent hiera_config':
      setting => 'hiera_config',
      value   => $hiera_config,
    }
  }
  if $binder != $::puppetconfig::params::agent::binder {
    ini_setting { 'agent binder':
      setting => 'binder',
      value   => $binder,
    }
  }
  if $binder_config != $::puppetconfig::params::agent::binder_config {
    ini_setting { 'agent binder_config':
      setting => 'binder_config',
      value   => $binder_config,
    }
  }
  if $catalog_terminus != $::puppetconfig::params::agent::catalog_terminus {
    ini_setting { 'agent catalog_terminus':
      setting => 'catalog_terminus',
      value   => $catalog_terminus,
    }
  }
  if $catalog_cache_terminus != $::puppetconfig::params::agent::catalog_cache_terminus {
    ini_setting { 'agent catalog_cache_terminus':
      setting => 'catalog_cache_terminus',
      value   => $catalog_cache_terminus,
    }
  }
  if $facts_terminus != $::puppetconfig::params::agent::facts_terminus {
    ini_setting { 'agent facts_terminus':
      setting => 'facts_terminus',
      value   => $facts_terminus,
    }
  }
  if $inventory_terminus != $::puppetconfig::params::agent::inventory_terminus {
    ini_setting { 'agent inventory_terminus':
      setting => 'inventory_terminus',
      value   => $inventory_terminus,
    }
  }
  if $default_file_terminus != $::puppetconfig::params::agent::default_file_terminus {
    ini_setting { 'agent default_file_terminus':
      setting => 'default_file_terminus',
      value   => $default_file_terminus,
    }
  }
  if $httplog != $::puppetconfig::params::agent::httplog {
    ini_setting { 'agent httplog':
      setting => 'httplog',
      value   => $httplog,
    }
  }
  if $http_proxy_host != $::puppetconfig::params::agent::http_proxy_host {
    ini_setting { 'agent http_proxy_host':
      setting => 'http_proxy_host',
      value   => $http_proxy_host,
    }
  }
  if $http_proxy_port != $::puppetconfig::params::agent::http_proxy_port {
    ini_setting { 'agent http_proxy_port':
      setting => 'http_proxy_port',
      value   => $http_proxy_port,
    }
  }
  if $filetimeout != $::puppetconfig::params::agent::filetimeout {
    ini_setting { 'agent filetimeout':
      setting => 'filetimeout',
      value   => $filetimeout,
    }
  }
  if $queue_type != $::puppetconfig::params::agent::queue_type {
    ini_setting { 'agent queue_type':
      setting => 'queue_type',
      value   => $queue_type,
    }
  }
  if $queue_source != $::puppetconfig::params::agent::queue_source {
    ini_setting { 'agent queue_source':
      setting => 'queue_source',
      value   => $queue_source,
    }
  }
  if $async_storeconfigs != $::puppetconfig::params::agent::async_storeconfigs {
    ini_setting { 'agent async_storeconfigs':
      setting => 'async_storeconfigs',
      value   => $async_storeconfigs,
    }
  }
  if $thin_storeconfigs != $::puppetconfig::params::agent::thin_storeconfigs {
    ini_setting { 'agent thin_storeconfigs':
      setting => 'thin_storeconfigs',
      value   => $thin_storeconfigs,
    }
  }
  if $config_version != $::puppetconfig::params::agent::config_version {
    ini_setting { 'agent config_version':
      setting => 'config_version',
      value   => $config_version,
    }
  }
  if $zlib != $::puppetconfig::params::agent::zlib {
    ini_setting { 'agent zlib':
      setting => 'zlib',
      value   => $zlib,
    }
  }
  if $prerun_command != $::puppetconfig::params::agent::prerun_command {
    ini_setting { 'agent prerun_command':
      setting => 'prerun_command',
      value   => $prerun_command,
    }
  }
  if $postrun_command != $::puppetconfig::params::agent::postrun_command {
    ini_setting { 'agent postrun_command':
      setting => 'postrun_command',
      value   => $postrun_command,
    }
  }
  if $freeze_main != $::puppetconfig::params::agent::freeze_main {
    ini_setting { 'agent freeze_main':
      setting => 'freeze_main',
      value   => $freeze_main,
    }
  }
  if $stringify_facts != $::puppetconfig::params::agent::stringify_facts {
    ini_setting { 'agent stringify_facts':
      setting => 'stringify_facts',
      value   => $stringify_facts,
    }
  }
  if $trusted_node_data != $::puppetconfig::params::agent::trusted_node_data {
    ini_setting { 'agent trusted_node_data':
      setting => 'trusted_node_data',
      value   => $trusted_node_data,
    }
  }
  if $certname != $::puppetconfig::params::agent::certname {
    ini_setting { 'agent certname':
      setting => 'certname',
      value   => $certname,
    }
  }
  if $certdnsnames != $::puppetconfig::params::agent::certdnsnames {
    ini_setting { 'agent certdnsnames':
      setting => 'certdnsnames',
      value   => $certdnsnames,
    }
  }
  if $dns_alt_names != $::puppetconfig::params::agent::dns_alt_names {
    ini_setting { 'agent dns_alt_names':
      setting => 'dns_alt_names',
      value   => $dns_alt_names,
    }
  }
  if $csr_attributes != $::puppetconfig::params::agent::csr_attributes {
    ini_setting { 'agent csr_attributes':
      setting => 'csr_attributes',
      value   => $csr_attributes,
    }
  }
  if $certdir != $::puppetconfig::params::agent::certdir {
    ini_setting { 'agent certdir':
      setting => 'certdir',
      value   => $certdir,
    }
  }
  if $ssldir != $::puppetconfig::params::agent::ssldir {
    ini_setting { 'agent ssldir':
      setting => 'ssldir',
      value   => $ssldir,
    }
  }
  if $publickeydir != $::puppetconfig::params::agent::publickeydir {
    ini_setting { 'agent publickeydir':
      setting => 'publickeydir',
      value   => $publickeydir,
    }
  }
  if $requestdir != $::puppetconfig::params::agent::requestdir {
    ini_setting { 'agent requestdir':
      setting => 'requestdir',
      value   => $requestdir,
    }
  }
  if $privatekeydir != $::puppetconfig::params::agent::privatekeydir {
    ini_setting { 'agent privatekeydir':
      setting => 'privatekeydir',
      value   => $privatekeydir,
    }
  }
  if $privatedir != $::puppetconfig::params::agent::privatedir {
    ini_setting { 'agent privatedir':
      setting => 'privatedir',
      value   => $privatedir,
    }
  }
  if $passfile != $::puppetconfig::params::agent::passfile {
    ini_setting { 'agent passfile':
      setting => 'passfile',
      value   => $passfile,
    }
  }
  if $hostcsr != $::puppetconfig::params::agent::hostcsr {
    ini_setting { 'agent hostcsr':
      setting => 'hostcsr',
      value   => $hostcsr,
    }
  }
  if $hostcert != $::puppetconfig::params::agent::hostcert {
    ini_setting { 'agent hostcert':
      setting => 'hostcert',
      value   => $hostcert,
    }
  }
  if $hostprivkey != $::puppetconfig::params::agent::hostprivkey {
    ini_setting { 'agent hostprivkey':
      setting => 'hostprivkey',
      value   => $hostprivkey,
    }
  }
  if $hostpubkey != $::puppetconfig::params::agent::hostpubkey {
    ini_setting { 'agent hostpubkey':
      setting => 'hostpubkey',
      value   => $hostpubkey,
    }
  }
  if $localcacert != $::puppetconfig::params::agent::localcacert {
    ini_setting { 'agent localcacert':
      setting => 'localcacert',
      value   => $localcacert,
    }
  }
  if $ssl_client_ca_auth != $::puppetconfig::params::agent::ssl_client_ca_auth {
    ini_setting { 'agent ssl_client_ca_auth':
      setting => 'ssl_client_ca_auth',
      value   => $ssl_client_ca_auth,
    }
  }
  if $ssl_server_ca_auth != $::puppetconfig::params::agent::ssl_server_ca_auth {
    ini_setting { 'agent ssl_server_ca_auth':
      setting => 'ssl_server_ca_auth',
      value   => $ssl_server_ca_auth,
    }
  }
  if $hostcrl != $::puppetconfig::params::agent::hostcrl {
    ini_setting { 'agent hostcrl':
      setting => 'hostcrl',
      value   => $hostcrl,
    }
  }
  if $certificate_revocation != $::puppetconfig::params::agent::certificate_revocation {
    ini_setting { 'agent certificate_revocation':
      setting => 'certificate_revocation',
      value   => $certificate_revocation,
    }
  }
  if $certificate_expire_warning != $::puppetconfig::params::agent::certificate_expire_warning {
    ini_setting { 'agent certificate_expire_warning':
      setting => 'certificate_expire_warning',
      value   => $certificate_expire_warning,
    }
  }
  if $plugindest != $::puppetconfig::params::agent::plugindest {
    ini_setting { 'agent plugindest':
      setting => 'plugindest',
      value   => $plugindest,
    }
  }
  if $pluginsource != $::puppetconfig::params::agent::pluginsource {
    ini_setting { 'agent pluginsource':
      setting => 'pluginsource',
      value   => $pluginsource,
    }
  }
  if $pluginfactdest != $::puppetconfig::params::agent::pluginfactdest {
    ini_setting { 'agent pluginfactdest':
      setting => 'pluginfactdest',
      value   => $pluginfactdest,
    }
  }
  if $pluginfactsource != $::puppetconfig::params::agent::pluginfactsource {
    ini_setting { 'agent pluginfactsource':
      setting => 'pluginfactsource',
      value   => $pluginfactsource,
    }
  }
  if $pluginsignore != $::puppetconfig::params::agent::pluginsignore {
    ini_setting { 'agent pluginsignore':
      setting => 'pluginsignore',
      value   => $pluginsignore,
    }
  }
  if $factpath != $::puppetconfig::params::agent::factpath {
    ini_setting { 'agent factpath':
      setting => 'factpath',
      value   => $factpath,
    }
  }
  if $external_nodes != $::puppetconfig::params::agent::external_nodes {
    ini_setting { 'agent external_nodes':
      setting => 'external_nodes',
      value   => $external_nodes,
    }
  }
  if $module_repository != $::puppetconfig::params::agent::module_repository {
    ini_setting { 'agent module_repository':
      setting => 'module_repository',
      value   => $module_repository,
    }
  }
  if $module_working_dir != $::puppetconfig::params::agent::module_working_dir {
    ini_setting { 'agent module_working_dir':
      setting => 'module_working_dir',
      value   => $module_working_dir,
    }
  }
  if $module_skeleton_dir != $::puppetconfig::params::agent::module_skeleton_dir {
    ini_setting { 'agent module_skeleton_dir':
      setting => 'module_skeleton_dir',
      value   => $module_skeleton_dir,
    }
  }
  if $ca_name != $::puppetconfig::params::agent::ca_name {
    ini_setting { 'agent ca_name':
      setting => 'ca_name',
      value   => $ca_name,
    }
  }
  if $cadir != $::puppetconfig::params::agent::cadir {
    ini_setting { 'agent cadir':
      setting => 'cadir',
      value   => $cadir,
    }
  }
  if $cacert != $::puppetconfig::params::agent::cacert {
    ini_setting { 'agent cacert':
      setting => 'cacert',
      value   => $cacert,
    }
  }
  if $cakey != $::puppetconfig::params::agent::cakey {
    ini_setting { 'agent cakey':
      setting => 'cakey',
      value   => $cakey,
    }
  }
  if $capub != $::puppetconfig::params::agent::capub {
    ini_setting { 'agent capub':
      setting => 'capub',
      value   => $capub,
    }
  }
  if $cacrl != $::puppetconfig::params::agent::cacrl {
    ini_setting { 'agent cacrl':
      setting => 'cacrl',
      value   => $cacrl,
    }
  }
  if $caprivatedir != $::puppetconfig::params::agent::caprivatedir {
    ini_setting { 'agent caprivatedir':
      setting => 'caprivatedir',
      value   => $caprivatedir,
    }
  }
  if $csrdir != $::puppetconfig::params::agent::csrdir {
    ini_setting { 'agent csrdir':
      setting => 'csrdir',
      value   => $csrdir,
    }
  }
  if $signeddir != $::puppetconfig::params::agent::signeddir {
    ini_setting { 'agent signeddir':
      setting => 'signeddir',
      value   => $signeddir,
    }
  }
  if $capass != $::puppetconfig::params::agent::capass {
    ini_setting { 'agent capass':
      setting => 'capass',
      value   => $capass,
    }
  }
  if $serial != $::puppetconfig::params::agent::serial {
    ini_setting { 'agent serial':
      setting => 'serial',
      value   => $serial,
    }
  }
  if $autosign != $::puppetconfig::params::agent::autosign {
    ini_setting { 'agent autosign':
      setting => 'autosign',
      value   => $autosign,
    }
  }
  if $allow_duplicate_certs != $::puppetconfig::params::agent::allow_duplicate_certs {
    ini_setting { 'agent allow_duplicate_certs':
      setting => 'allow_duplicate_certs',
      value   => $allow_duplicate_certs,
    }
  }
  if $ca_ttl != $::puppetconfig::params::agent::ca_ttl {
    ini_setting { 'agent ca_ttl':
      setting => 'ca_ttl',
      value   => $ca_ttl,
    }
  }
  if $req_bits != $::puppetconfig::params::agent::req_bits {
    ini_setting { 'agent req_bits':
      setting => 'req_bits',
      value   => $req_bits,
    }
  }
  if $keylength != $::puppetconfig::params::agent::keylength {
    ini_setting { 'agent keylength':
      setting => 'keylength',
      value   => $keylength,
    }
  }
  if $cert_inventory != $::puppetconfig::params::agent::cert_inventory {
    ini_setting { 'agent cert_inventory':
      setting => 'cert_inventory',
      value   => $cert_inventory,
    }
  }
  if $config_file_name != $::puppetconfig::params::agent::config_file_name {
    ini_setting { 'agent config_file_name':
      setting => 'config_file_name',
      value   => $config_file_name,
    }
  }
  if $config != $::puppetconfig::params::agent::config {
    ini_setting { 'agent config':
      setting => 'config',
      value   => $config,
    }
  }
  if $pidfile != $::puppetconfig::params::agent::pidfile {
    ini_setting { 'agent pidfile':
      setting => 'pidfile',
      value   => $pidfile,
    }
  }
  if $bindaddress != $::puppetconfig::params::agent::bindaddress {
    ini_setting { 'agent bindaddress':
      setting => 'bindaddress',
      value   => $bindaddress,
    }
  }
  if $user != $::puppetconfig::params::agent::user {
    ini_setting { 'agent user':
      setting => 'user',
      value   => $user,
    }
  }
  if $group != $::puppetconfig::params::agent::group {
    ini_setting { 'agent group':
      setting => 'group',
      value   => $group,
    }
  }
  if $manifestdir != $::puppetconfig::params::agent::manifestdir {
    ini_setting { 'agent manifestdir':
      setting => 'manifestdir',
      value   => $manifestdir,
    }
  }
  if $manifest != $::puppetconfig::params::agent::manifest {
    ini_setting { 'agent manifest':
      setting => 'manifest',
      value   => $manifest,
    }
  }
  if $code != $::puppetconfig::params::agent::code {
    ini_setting { 'agent code':
      setting => 'code',
      value   => $code,
    }
  }
  if $masterlog != $::puppetconfig::params::agent::masterlog {
    ini_setting { 'agent masterlog':
      setting => 'masterlog',
      value   => $masterlog,
    }
  }
  if $masterhttplog != $::puppetconfig::params::agent::masterhttplog {
    ini_setting { 'agent masterhttplog':
      setting => 'masterhttplog',
      value   => $masterhttplog,
    }
  }
  if $masterport != $::puppetconfig::params::agent::masterport {
    ini_setting { 'agent masterport':
      setting => 'masterport',
      value   => $masterport,
    }
  }
  if $node_name != $::puppetconfig::params::agent::node_name {
    ini_setting { 'agent node_name':
      setting => 'node_name',
      value   => $node_name,
    }
  }
  if $bucketdir != $::puppetconfig::params::agent::bucketdir {
    ini_setting { 'agent bucketdir':
      setting => 'bucketdir',
      value   => $bucketdir,
    }
  }
  if $rest_authconfig != $::puppetconfig::params::agent::rest_authconfig {
    ini_setting { 'agent rest_authconfig':
      setting => 'rest_authconfig',
      value   => $rest_authconfig,
    }
  }
  if $ca != $::puppetconfig::params::agent::ca {
    ini_setting { 'agent ca':
      setting => 'ca',
      value   => $ca,
    }
  }
  if $modulepath != $::puppetconfig::params::agent::modulepath {
    ini_setting { 'agent modulepath':
      setting => 'modulepath',
      value   => $modulepath,
    }
  }
  if $ssl_client_header != $::puppetconfig::params::agent::ssl_client_header {
    ini_setting { 'agent ssl_client_header':
      setting => 'ssl_client_header',
      value   => $ssl_client_header,
    }
  }
  if $ssl_client_verify_header != $::puppetconfig::params::agent::ssl_client_verify_header {
    ini_setting { 'agent ssl_client_verify_header':
      setting => 'ssl_client_verify_header',
      value   => $ssl_client_verify_header,
    }
  }
  if $yamldir != $::puppetconfig::params::agent::yamldir {
    ini_setting { 'agent yamldir':
      setting => 'yamldir',
      value   => $yamldir,
    }
  }
  if $server_datadir != $::puppetconfig::params::agent::server_datadir {
    ini_setting { 'agent server_datadir':
      setting => 'server_datadir',
      value   => $server_datadir,
    }
  }
  if $reportdir != $::puppetconfig::params::agent::reportdir {
    ini_setting { 'agent reportdir':
      setting => 'reportdir',
      value   => $reportdir,
    }
  }
  if $reporturl != $::puppetconfig::params::agent::reporturl {
    ini_setting { 'agent reporturl':
      setting => 'reporturl',
      value   => $reporturl,
    }
  }
  if $fileserverconfig != $::puppetconfig::params::agent::fileserverconfig {
    ini_setting { 'agent fileserverconfig':
      setting => 'fileserverconfig',
      value   => $fileserverconfig,
    }
  }
  if $strict_hostname_checking != $::puppetconfig::params::agent::strict_hostname_checking {
    ini_setting { 'agent strict_hostname_checking':
      setting => 'strict_hostname_checking',
      value   => $strict_hostname_checking,
    }
  }
  if $storeconfigs != $::puppetconfig::params::agent::storeconfigs {
    ini_setting { 'agent storeconfigs':
      setting => 'storeconfigs',
      value   => $storeconfigs,
    }
  }
  if $storeconfigs_backend != $::puppetconfig::params::agent::storeconfigs_backend {
    ini_setting { 'agent storeconfigs_backend':
      setting => 'storeconfigs_backend',
      value   => $storeconfigs_backend,
    }
  }
  if $rrddir != $::puppetconfig::params::agent::rrddir {
    ini_setting { 'agent rrddir':
      setting => 'rrddir',
      value   => $rrddir,
    }
  }
  if $rrdinterval != $::puppetconfig::params::agent::rrdinterval {
    ini_setting { 'agent rrdinterval':
      setting => 'rrdinterval',
      value   => $rrdinterval,
    }
  }
  if $devicedir != $::puppetconfig::params::agent::devicedir {
    ini_setting { 'agent devicedir':
      setting => 'devicedir',
      value   => $devicedir,
    }
  }
  if $deviceconfig != $::puppetconfig::params::agent::deviceconfig {
    ini_setting { 'agent deviceconfig':
      setting => 'deviceconfig',
      value   => $deviceconfig,
    }
  }
  if $node_name_value != $::puppetconfig::params::agent::node_name_value {
    ini_setting { 'agent node_name_value':
      setting => 'node_name_value',
      value   => $node_name_value,
    }
  }
  if $node_name_fact != $::puppetconfig::params::agent::node_name_fact {
    ini_setting { 'agent node_name_fact':
      setting => 'node_name_fact',
      value   => $node_name_fact,
    }
  }
  if $statefile != $::puppetconfig::params::agent::statefile {
    ini_setting { 'agent statefile':
      setting => 'statefile',
      value   => $statefile,
    }
  }
  if $clientyamldir != $::puppetconfig::params::agent::clientyamldir {
    ini_setting { 'agent clientyamldir':
      setting => 'clientyamldir',
      value   => $clientyamldir,
    }
  }
  if $client_datadir != $::puppetconfig::params::agent::client_datadir {
    ini_setting { 'agent client_datadir':
      setting => 'client_datadir',
      value   => $client_datadir,
    }
  }
  if $resourcefile != $::puppetconfig::params::agent::resourcefile {
    ini_setting { 'agent resourcefile':
      setting => 'resourcefile',
      value   => $resourcefile,
    }
  }
  if $puppetdlog != $::puppetconfig::params::agent::puppetdlog {
    ini_setting { 'agent puppetdlog':
      setting => 'puppetdlog',
      value   => $puppetdlog,
    }
  }
  if $server != $::puppetconfig::params::agent::server {
    ini_setting { 'agent server':
      setting => 'server',
      value   => $server,
    }
  }
  if $use_srv_records != $::puppetconfig::params::agent::use_srv_records {
    ini_setting { 'agent use_srv_records':
      setting => 'use_srv_records',
      value   => $use_srv_records,
    }
  }
  if $srv_domain != $::puppetconfig::params::agent::srv_domain {
    ini_setting { 'agent srv_domain':
      setting => 'srv_domain',
      value   => $srv_domain,
    }
  }
  if $ignoreschedules != $::puppetconfig::params::agent::ignoreschedules {
    ini_setting { 'agent ignoreschedules':
      setting => 'ignoreschedules',
      value   => $ignoreschedules,
    }
  }
  if $default_schedules != $::puppetconfig::params::agent::default_schedules {
    ini_setting { 'agent default_schedules':
      setting => 'default_schedules',
      value   => $default_schedules,
    }
  }
  if $puppetport != $::puppetconfig::params::agent::puppetport {
    ini_setting { 'agent puppetport':
      setting => 'puppetport',
      value   => $puppetport,
    }
  }
  if $runinterval != $::puppetconfig::params::agent::runinterval {
    ini_setting { 'agent runinterval':
      setting => 'runinterval',
      value   => $runinterval,
    }
  }
  if $listen != $::puppetconfig::params::agent::listen {
    ini_setting { 'agent listen':
      setting => 'listen',
      value   => $listen,
    }
  }
  if $ca_server != $::puppetconfig::params::agent::ca_server {
    ini_setting { 'agent ca_server':
      setting => 'ca_server',
      value   => $ca_server,
    }
  }
  if $ca_port != $::puppetconfig::params::agent::ca_port {
    ini_setting { 'agent ca_port':
      setting => 'ca_port',
      value   => $ca_port,
    }
  }
  if $catalog_format != $::puppetconfig::params::agent::catalog_format {
    ini_setting { 'agent catalog_format':
      setting => 'catalog_format',
      value   => $catalog_format,
    }
  }
  if $preferred_serialization_format != $::puppetconfig::params::agent::preferred_serialization_format {
    ini_setting { 'agent preferred_serialization_format':
      setting => 'preferred_serialization_format',
      value   => $preferred_serialization_format,
    }
  }
  if $report_serialization_format != $::puppetconfig::params::agent::report_serialization_format {
    ini_setting { 'agent report_serialization_format':
      setting => 'report_serialization_format',
      value   => $report_serialization_format,
    }
  }
  if $legacy_query_parameter_serialization != $::puppetconfig::params::agent::legacy_query_parameter_serialization {
    ini_setting { 'agent legacy_query_parameter_serialization':
      setting => 'legacy_query_parameter_serialization',
      value   => $legacy_query_parameter_serialization,
    }
  }
  if $agent_catalog_run_lockfile != $::puppetconfig::params::agent::agent_catalog_run_lockfile {
    ini_setting { 'agent agent_catalog_run_lockfile':
      setting => 'agent_catalog_run_lockfile',
      value   => $agent_catalog_run_lockfile,
    }
  }
  if $agent_disabled_lockfile != $::puppetconfig::params::agent::agent_disabled_lockfile {
    ini_setting { 'agent agent_disabled_lockfile':
      setting => 'agent_disabled_lockfile',
      value   => $agent_disabled_lockfile,
    }
  }
  if $usecacheonfailure != $::puppetconfig::params::agent::usecacheonfailure {
    ini_setting { 'agent usecacheonfailure':
      setting => 'usecacheonfailure',
      value   => $usecacheonfailure,
    }
  }
  if $use_cached_catalog != $::puppetconfig::params::agent::use_cached_catalog {
    ini_setting { 'agent use_cached_catalog':
      setting => 'use_cached_catalog',
      value   => $use_cached_catalog,
    }
  }
  if $ignoremissingtypes != $::puppetconfig::params::agent::ignoremissingtypes {
    ini_setting { 'agent ignoremissingtypes':
      setting => 'ignoremissingtypes',
      value   => $ignoremissingtypes,
    }
  }
  if $ignorecache != $::puppetconfig::params::agent::ignorecache {
    ini_setting { 'agent ignorecache':
      setting => 'ignorecache',
      value   => $ignorecache,
    }
  }
  if $dynamicfacts != $::puppetconfig::params::agent::dynamicfacts {
    ini_setting { 'agent dynamicfacts':
      setting => 'dynamicfacts',
      value   => $dynamicfacts,
    }
  }
  if $splaylimit != $::puppetconfig::params::agent::splaylimit {
    ini_setting { 'agent splaylimit':
      setting => 'splaylimit',
      value   => $splaylimit,
    }
  }
  if $splay != $::puppetconfig::params::agent::splay {
    ini_setting { 'agent splay':
      setting => 'splay',
      value   => $splay,
    }
  }
  if $clientbucketdir != $::puppetconfig::params::agent::clientbucketdir {
    ini_setting { 'agent clientbucketdir':
      setting => 'clientbucketdir',
      value   => $clientbucketdir,
    }
  }
  if $configtimeout != $::puppetconfig::params::agent::configtimeout {
    ini_setting { 'agent configtimeout':
      setting => 'configtimeout',
      value   => $configtimeout,
    }
  }
  if $report_server != $::puppetconfig::params::agent::report_server {
    ini_setting { 'agent report_server':
      setting => 'report_server',
      value   => $report_server,
    }
  }
  if $report_port != $::puppetconfig::params::agent::report_port {
    ini_setting { 'agent report_port':
      setting => 'report_port',
      value   => $report_port,
    }
  }
  if $inventory_server != $::puppetconfig::params::agent::inventory_server {
    ini_setting { 'agent inventory_server':
      setting => 'inventory_server',
      value   => $inventory_server,
    }
  }
  if $inventory_port != $::puppetconfig::params::agent::inventory_port {
    ini_setting { 'agent inventory_port':
      setting => 'inventory_port',
      value   => $inventory_port,
    }
  }
  if $report != $::puppetconfig::params::agent::report {
    ini_setting { 'agent report':
      setting => 'report',
      value   => $report,
    }
  }
  if $lastrunfile != $::puppetconfig::params::agent::lastrunfile {
    ini_setting { 'agent lastrunfile':
      setting => 'lastrunfile',
      value   => $lastrunfile,
    }
  }
  if $lastrunreport != $::puppetconfig::params::agent::lastrunreport {
    ini_setting { 'agent lastrunreport':
      setting => 'lastrunreport',
      value   => $lastrunreport,
    }
  }
  if $graphdir != $::puppetconfig::params::agent::graphdir {
    ini_setting { 'agent graphdir':
      setting => 'graphdir',
      value   => $graphdir,
    }
  }
  if $http_compression != $::puppetconfig::params::agent::http_compression {
    ini_setting { 'agent http_compression':
      setting => 'http_compression',
      value   => $http_compression,
    }
  }
  if $waitforcert != $::puppetconfig::params::agent::waitforcert {
    ini_setting { 'agent waitforcert':
      setting => 'waitforcert',
      value   => $waitforcert,
    }
  }
  if $ordering != $::puppetconfig::params::agent::ordering {
    ini_setting { 'agent ordering':
      setting => 'ordering',
      value   => $ordering,
    }
  }
  if $archive_files != $::puppetconfig::params::agent::archive_files {
    ini_setting { 'agent archive_files':
      setting => 'archive_files',
      value   => $archive_files,
    }
  }
  if $archive_file_server != $::puppetconfig::params::agent::archive_file_server {
    ini_setting { 'agent archive_file_server':
      setting => 'archive_file_server',
      value   => $archive_file_server,
    }
  }
  if $tagmap != $::puppetconfig::params::agent::tagmap {
    ini_setting { 'agent tagmap':
      setting => 'tagmap',
      value   => $tagmap,
    }
  }
  if $sendmail != $::puppetconfig::params::agent::sendmail {
    ini_setting { 'agent sendmail':
      setting => 'sendmail',
      value   => $sendmail,
    }
  }
  if $reportfrom != $::puppetconfig::params::agent::reportfrom {
    ini_setting { 'agent reportfrom':
      setting => 'reportfrom',
      value   => $reportfrom,
    }
  }
  if $smtpserver != $::puppetconfig::params::agent::smtpserver {
    ini_setting { 'agent smtpserver':
      setting => 'smtpserver',
      value   => $smtpserver,
    }
  }
  if $smtpport != $::puppetconfig::params::agent::smtpport {
    ini_setting { 'agent smtpport':
      setting => 'smtpport',
      value   => $smtpport,
    }
  }
  if $smtphelo != $::puppetconfig::params::agent::smtphelo {
    ini_setting { 'agent smtphelo':
      setting => 'smtphelo',
      value   => $smtphelo,
    }
  }
  if $dblocation != $::puppetconfig::params::agent::dblocation {
    ini_setting { 'agent dblocation':
      setting => 'dblocation',
      value   => $dblocation,
    }
  }
  if $dbadapter != $::puppetconfig::params::agent::dbadapter {
    ini_setting { 'agent dbadapter':
      setting => 'dbadapter',
      value   => $dbadapter,
    }
  }
  if $dbmigrate != $::puppetconfig::params::agent::dbmigrate {
    ini_setting { 'agent dbmigrate':
      setting => 'dbmigrate',
      value   => $dbmigrate,
    }
  }
  if $dbname != $::puppetconfig::params::agent::dbname {
    ini_setting { 'agent dbname':
      setting => 'dbname',
      value   => $dbname,
    }
  }
  if $dbserver != $::puppetconfig::params::agent::dbserver {
    ini_setting { 'agent dbserver':
      setting => 'dbserver',
      value   => $dbserver,
    }
  }
  if $dbport != $::puppetconfig::params::agent::dbport {
    ini_setting { 'agent dbport':
      setting => 'dbport',
      value   => $dbport,
    }
  }
  if $dbuser != $::puppetconfig::params::agent::dbuser {
    ini_setting { 'agent dbuser':
      setting => 'dbuser',
      value   => $dbuser,
    }
  }
  if $dbpassword != $::puppetconfig::params::agent::dbpassword {
    ini_setting { 'agent dbpassword':
      setting => 'dbpassword',
      value   => $dbpassword,
    }
  }
  if $dbconnections != $::puppetconfig::params::agent::dbconnections {
    ini_setting { 'agent dbconnections':
      setting => 'dbconnections',
      value   => $dbconnections,
    }
  }
  if $dbsocket != $::puppetconfig::params::agent::dbsocket {
    ini_setting { 'agent dbsocket':
      setting => 'dbsocket',
      value   => $dbsocket,
    }
  }
  if $railslog != $::puppetconfig::params::agent::railslog {
    ini_setting { 'agent railslog':
      setting => 'railslog',
      value   => $railslog,
    }
  }
  if $rails_loglevel != $::puppetconfig::params::agent::rails_loglevel {
    ini_setting { 'agent rails_loglevel':
      setting => 'rails_loglevel',
      value   => $rails_loglevel,
    }
  }
  if $couchdb_url != $::puppetconfig::params::agent::couchdb_url {
    ini_setting { 'agent couchdb_url':
      setting => 'couchdb_url',
      value   => $couchdb_url,
    }
  }
  if $tags != $::puppetconfig::params::agent::tags {
    ini_setting { 'agent tags':
      setting => 'tags',
      value   => $tags,
    }
  }
  if $evaltrace != $::puppetconfig::params::agent::evaltrace {
    ini_setting { 'agent evaltrace':
      setting => 'evaltrace',
      value   => $evaltrace,
    }
  }
  if $summarize != $::puppetconfig::params::agent::summarize {
    ini_setting { 'agent summarize':
      setting => 'summarize',
      value   => $summarize,
    }
  }
  if $ldapssl != $::puppetconfig::params::agent::ldapssl {
    ini_setting { 'agent ldapssl':
      setting => 'ldapssl',
      value   => $ldapssl,
    }
  }
  if $ldaptls != $::puppetconfig::params::agent::ldaptls {
    ini_setting { 'agent ldaptls':
      setting => 'ldaptls',
      value   => $ldaptls,
    }
  }
  if $ldapserver != $::puppetconfig::params::agent::ldapserver {
    ini_setting { 'agent ldapserver':
      setting => 'ldapserver',
      value   => $ldapserver,
    }
  }
  if $ldapport != $::puppetconfig::params::agent::ldapport {
    ini_setting { 'agent ldapport':
      setting => 'ldapport',
      value   => $ldapport,
    }
  }
  if $ldapstring != $::puppetconfig::params::agent::ldapstring {
    ini_setting { 'agent ldapstring':
      setting => 'ldapstring',
      value   => $ldapstring,
    }
  }
  if $ldapclassattrs != $::puppetconfig::params::agent::ldapclassattrs {
    ini_setting { 'agent ldapclassattrs':
      setting => 'ldapclassattrs',
      value   => $ldapclassattrs,
    }
  }
  if $ldapstackedattrs != $::puppetconfig::params::agent::ldapstackedattrs {
    ini_setting { 'agent ldapstackedattrs':
      setting => 'ldapstackedattrs',
      value   => $ldapstackedattrs,
    }
  }
  if $ldapattrs != $::puppetconfig::params::agent::ldapattrs {
    ini_setting { 'agent ldapattrs':
      setting => 'ldapattrs',
      value   => $ldapattrs,
    }
  }
  if $ldapparentattr != $::puppetconfig::params::agent::ldapparentattr {
    ini_setting { 'agent ldapparentattr':
      setting => 'ldapparentattr',
      value   => $ldapparentattr,
    }
  }
  if $ldapuser != $::puppetconfig::params::agent::ldapuser {
    ini_setting { 'agent ldapuser':
      setting => 'ldapuser',
      value   => $ldapuser,
    }
  }
  if $ldappassword != $::puppetconfig::params::agent::ldappassword {
    ini_setting { 'agent ldappassword':
      setting => 'ldappassword',
      value   => $ldappassword,
    }
  }
  if $ldapbase != $::puppetconfig::params::agent::ldapbase {
    ini_setting { 'agent ldapbase':
      setting => 'ldapbase',
      value   => $ldapbase,
    }
  }
  if $templatedir != $::puppetconfig::params::agent::templatedir {
    ini_setting { 'agent templatedir':
      setting => 'templatedir',
      value   => $templatedir,
    }
  }
  if $allow_variables_with_dashes != $::puppetconfig::params::agent::allow_variables_with_dashes {
    ini_setting { 'agent allow_variables_with_dashes':
      setting => 'allow_variables_with_dashes',
      value   => $allow_variables_with_dashes,
    }
  }
  if $parser != $::puppetconfig::params::agent::parser {
    ini_setting { 'agent parser':
      setting => 'parser',
      value   => $parser,
    }
  }
  if $max_errors != $::puppetconfig::params::agent::max_errors {
    ini_setting { 'agent max_errors':
      setting => 'max_errors',
      value   => $max_errors,
    }
  }
  if $max_warnings != $::puppetconfig::params::agent::max_warnings {
    ini_setting { 'agent max_warnings':
      setting => 'max_warnings',
      value   => $max_warnings,
    }
  }
  if $max_deprecations != $::puppetconfig::params::agent::max_deprecations {
    ini_setting { 'agent max_deprecations':
      setting => 'max_deprecations',
      value   => $max_deprecations,
    }
  }
  if $document_all != $::puppetconfig::params::agent::document_all {
    ini_setting { 'agent document_all':
      setting => 'document_all',
      value   => $document_all,
    }
  }
}
