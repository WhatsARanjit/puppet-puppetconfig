class puppetconfig::master (
  $agent_catalog_run_lockfile           = $puppetconfig::params::master::agent_catalog_run_lockfile,
  $agent_disabled_lockfile              = $puppetconfig::params::master::agent_disabled_lockfile,
  $allow_duplicate_certs                = $puppetconfig::params::master::allow_duplicate_certs,
  $allow_variables_with_dashes          = $puppetconfig::params::master::allow_variables_with_dashes,
  $archive_file_server                  = $puppetconfig::params::master::archive_file_server,
  $archive_files                        = $puppetconfig::params::master::archive_files,
  $async_storeconfigs                   = $puppetconfig::params::master::async_storeconfigs,
  $autoflush                            = $puppetconfig::params::master::autoflush,
  $autosign                             = $puppetconfig::params::master::autosign,
  $bindaddress                          = $puppetconfig::params::master::bindaddress,
  $binder_config                        = $puppetconfig::params::master::binder_config,
  $binder                               = $puppetconfig::params::master::binder,
  $bucketdir                            = $puppetconfig::params::master::bucketdir,
  $cacert                               = $puppetconfig::params::master::cacert,
  $cacrl                                = $puppetconfig::params::master::cacrl,
  $cadir                                = $puppetconfig::params::master::cadir,
  $cakey                                = $puppetconfig::params::master::cakey,
  $ca_name                              = $puppetconfig::params::master::ca_name,
  $capass                               = $puppetconfig::params::master::capass,
  $ca_port                              = $puppetconfig::params::master::ca_port,
  $caprivatedir                         = $puppetconfig::params::master::caprivatedir,
  $capub                                = $puppetconfig::params::master::capub,
  $ca                                   = $puppetconfig::params::master::ca,
  $ca_server                            = $puppetconfig::params::master::ca_server,
  $catalog_cache_terminus               = $puppetconfig::params::master::catalog_cache_terminus,
  $catalog_format                       = $puppetconfig::params::master::catalog_format,
  $catalog_terminus                     = $puppetconfig::params::master::catalog_terminus,
  $ca_ttl                               = $puppetconfig::params::master::ca_ttl,
  $certdir                              = $puppetconfig::params::master::certdir,
  $certdnsnames                         = $puppetconfig::params::master::certdnsnames,
  $certificate_expire_warning           = $puppetconfig::params::master::certificate_expire_warning,
  $certificate_revocation               = $puppetconfig::params::master::certificate_revocation,
  $cert_inventory                       = $puppetconfig::params::master::cert_inventory,
  $certname                             = $puppetconfig::params::master::certname,
  $classfile                            = $puppetconfig::params::master::classfile,
  $clientbucketdir                      = $puppetconfig::params::master::clientbucketdir,
  $client_datadir                       = $puppetconfig::params::master::client_datadir,
  $clientyamldir                        = $puppetconfig::params::master::clientyamldir,
  $code                                 = $puppetconfig::params::master::code,
  $color                                = $puppetconfig::params::master::color,
  $confdir                              = $puppetconfig::params::master::confdir,
  $config_file_name                     = $puppetconfig::params::master::config_file_name,
  $configprint                          = $puppetconfig::params::master::configprint,
  $config                               = $puppetconfig::params::master::config,
  $configtimeout                        = $puppetconfig::params::master::configtimeout,
  $config_version                       = $puppetconfig::params::master::config_version,
  $couchdb_url                          = $puppetconfig::params::master::couchdb_url,
  $csr_attributes                       = $puppetconfig::params::master::csr_attributes,
  $csrdir                               = $puppetconfig::params::master::csrdir,
  $daemonize                            = $puppetconfig::params::master::daemonize,
  $data_binding_terminus                = $puppetconfig::params::master::data_binding_terminus,
  $dbadapter                            = $puppetconfig::params::master::dbadapter,
  $dbconnections                        = $puppetconfig::params::master::dbconnections,
  $dblocation                           = $puppetconfig::params::master::dblocation,
  $dbmigrate                            = $puppetconfig::params::master::dbmigrate,
  $dbname                               = $puppetconfig::params::master::dbname,
  $dbpassword                           = $puppetconfig::params::master::dbpassword,
  $dbport                               = $puppetconfig::params::master::dbport,
  $dbserver                             = $puppetconfig::params::master::dbserver,
  $dbsocket                             = $puppetconfig::params::master::dbsocket,
  $dbuser                               = $puppetconfig::params::master::dbuser,
  $default_file_terminus                = $puppetconfig::params::master::default_file_terminus,
  $default_schedules                    = $puppetconfig::params::master::default_schedules,
  $deviceconfig                         = $puppetconfig::params::master::deviceconfig,
  $devicedir                            = $puppetconfig::params::master::devicedir,
  $diff_args                            = $puppetconfig::params::master::diff_args,
  $diff                                 = $puppetconfig::params::master::diff,
  $dns_alt_names                        = $puppetconfig::params::master::dns_alt_names,
  $document_all                         = $puppetconfig::params::master::document_all,
  $dynamicfacts                         = $puppetconfig::params::master::dynamicfacts,
  $environment                          = $puppetconfig::params::master::environment,
  $evaltrace                            = $puppetconfig::params::master::evaltrace,
  $external_nodes                       = $puppetconfig::params::master::external_nodes,
  $factpath                             = $puppetconfig::params::master::factpath,
  $facts_terminus                       = $puppetconfig::params::master::facts_terminus,
  $fileserverconfig                     = $puppetconfig::params::master::fileserverconfig,
  $filetimeout                          = $puppetconfig::params::master::filetimeout,
  $freeze_main                          = $puppetconfig::params::master::freeze_main,
  $genmanifest                          = $puppetconfig::params::master::genmanifest,
  $graphdir                             = $puppetconfig::params::master::graphdir,
  $graph                                = $puppetconfig::params::master::graph,
  $group                                = $puppetconfig::params::master::group,
  $hiera_config                         = $puppetconfig::params::master::hiera_config,
  $hostcert                             = $puppetconfig::params::master::hostcert,
  $hostcrl                              = $puppetconfig::params::master::hostcrl,
  $hostcsr                              = $puppetconfig::params::master::hostcsr,
  $hostprivkey                          = $puppetconfig::params::master::hostprivkey,
  $hostpubkey                           = $puppetconfig::params::master::hostpubkey,
  $http_compression                     = $puppetconfig::params::master::http_compression,
  $httplog                              = $puppetconfig::params::master::httplog,
  $http_proxy_host                      = $puppetconfig::params::master::http_proxy_host,
  $http_proxy_port                      = $puppetconfig::params::master::http_proxy_port,
  $ignorecache                          = $puppetconfig::params::master::ignorecache,
  $ignoreimport                         = $puppetconfig::params::master::ignoreimport,
  $ignoremissingtypes                   = $puppetconfig::params::master::ignoremissingtypes,
  $ignoreschedules                      = $puppetconfig::params::master::ignoreschedules,
  $inventory_port                       = $puppetconfig::params::master::inventory_port,
  $inventory_server                     = $puppetconfig::params::master::inventory_server,
  $inventory_terminus                   = $puppetconfig::params::master::inventory_terminus,
  $keylength                            = $puppetconfig::params::master::keylength,
  $lastrunfile                          = $puppetconfig::params::master::lastrunfile,
  $lastrunreport                        = $puppetconfig::params::master::lastrunreport,
  $ldapattrs                            = $puppetconfig::params::master::ldapattrs,
  $ldapbase                             = $puppetconfig::params::master::ldapbase,
  $ldapclassattrs                       = $puppetconfig::params::master::ldapclassattrs,
  $ldapparentattr                       = $puppetconfig::params::master::ldapparentattr,
  $ldappassword                         = $puppetconfig::params::master::ldappassword,
  $ldapport                             = $puppetconfig::params::master::ldapport,
  $ldapserver                           = $puppetconfig::params::master::ldapserver,
  $ldapssl                              = $puppetconfig::params::master::ldapssl,
  $ldapstackedattrs                     = $puppetconfig::params::master::ldapstackedattrs,
  $ldapstring                           = $puppetconfig::params::master::ldapstring,
  $ldaptls                              = $puppetconfig::params::master::ldaptls,
  $ldapuser                             = $puppetconfig::params::master::ldapuser,
  $legacy_query_parameter_serialization = $puppetconfig::params::master::legacy_query_parameter_serialization,
  $libdir                               = $puppetconfig::params::master::libdir,
  $listen                               = $puppetconfig::params::master::listen,
  $localcacert                          = $puppetconfig::params::master::localcacert,
  $localconfig                          = $puppetconfig::params::master::localconfig,
  $logdir                               = $puppetconfig::params::master::logdir,
  $manage_internal_file_permissions     = $puppetconfig::params::master::manage_internal_file_permissions,
  $manifestdir                          = $puppetconfig::params::master::manifestdir,
  $manifest                             = $puppetconfig::params::master::manifest,
  $masterhttplog                        = $puppetconfig::params::master::masterhttplog,
  $masterlog                            = $puppetconfig::params::master::masterlog,
  $masterport                           = $puppetconfig::params::master::masterport,
  $max_deprecations                     = $puppetconfig::params::master::max_deprecations,
  $max_errors                           = $puppetconfig::params::master::max_errors,
  $maximum_uid                          = $puppetconfig::params::master::maximum_uid,
  $max_warnings                         = $puppetconfig::params::master::max_warnings,
  $mkusers                              = $puppetconfig::params::master::mkusers,
  $modulepath                           = $puppetconfig::params::master::modulepath,
  $module_repository                    = $puppetconfig::params::master::module_repository,
  $module_skeleton_dir                  = $puppetconfig::params::master::module_skeleton_dir,
  $module_working_dir                   = $puppetconfig::params::master::module_working_dir,
  $node_cache_terminus                  = $puppetconfig::params::master::node_cache_terminus,
  $node_name_fact                       = $puppetconfig::params::master::node_name_fact,
  $node_name                            = $puppetconfig::params::master::node_name,
  $node_name_value                      = $puppetconfig::params::master::node_name_value,
  $node_terminus                        = $puppetconfig::params::master::node_terminus,
  $no_op                                = $puppetconfig::params::master::no_op,
  $onetime                              = $puppetconfig::params::master::onetime,
  $ordering                             = $puppetconfig::params::master::ordering,
  $parser                               = $puppetconfig::params::master::parser,
  $passfile                             = $puppetconfig::params::master::passfile,
  $path                                 = $puppetconfig::params::master::path,
  $pidfile                              = $puppetconfig::params::master::pidfile,
  $plugindest                           = $puppetconfig::params::master::plugindest,
  $pluginfactdest                       = $puppetconfig::params::master::pluginfactdest,
  $pluginfactsource                     = $puppetconfig::params::master::pluginfactsource,
  $pluginsignore                        = $puppetconfig::params::master::pluginsignore,
  $pluginsource                         = $puppetconfig::params::master::pluginsource,
  $pluginsync                           = $puppetconfig::params::master::pluginsync,
  $postrun_command                      = $puppetconfig::params::master::postrun_command,
  $preferred_serialization_format       = $puppetconfig::params::master::preferred_serialization_format,
  $prerun_command                       = $puppetconfig::params::master::prerun_command,
  $priority                             = $puppetconfig::params::master::priority,
  $privatedir                           = $puppetconfig::params::master::privatedir,
  $privatekeydir                        = $puppetconfig::params::master::privatekeydir,
  $profile                              = $puppetconfig::params::master::profile,
  $publickeydir                         = $puppetconfig::params::master::publickeydir,
  $puppetdlog                           = $puppetconfig::params::master::puppetdlog,
  $puppetport                           = $puppetconfig::params::master::puppetport,
  $queue_source                         = $puppetconfig::params::master::queue_source,
  $queue_type                           = $puppetconfig::params::master::queue_type,
  $rails_loglevel                       = $puppetconfig::params::master::rails_loglevel,
  $railslog                             = $puppetconfig::params::master::railslog,
  $reportdir                            = $puppetconfig::params::master::reportdir,
  $reportfrom                           = $puppetconfig::params::master::reportfrom,
  $report_port                          = $puppetconfig::params::master::report_port,
  $report                               = $puppetconfig::params::master::report,
  $report_serialization_format          = $puppetconfig::params::master::report_serialization_format,
  $report_server                        = $puppetconfig::params::master::report_server,
  $reports                              = $puppetconfig::params::master::reports,
  $reporturl                            = $puppetconfig::params::master::reporturl,
  $req_bits                             = $puppetconfig::params::master::req_bits,
  $requestdir                           = $puppetconfig::params::master::requestdir,
  $resourcefile                         = $puppetconfig::params::master::resourcefile,
  $rest_authconfig                      = $puppetconfig::params::master::rest_authconfig,
  $route_file                           = $puppetconfig::params::master::route_file,
  $rrddir                               = $puppetconfig::params::master::rrddir,
  $rrdinterval                          = $puppetconfig::params::master::rrdinterval,
  $rundir                               = $puppetconfig::params::master::rundir,
  $runinterval                          = $puppetconfig::params::master::runinterval,
  $section                              = $puppetconfig::params::master::section,
  $sendmail                             = $puppetconfig::params::master::sendmail,
  $serial                               = $puppetconfig::params::master::serial,
  $server_datadir                       = $puppetconfig::params::master::server_datadir,
  $server                               = $puppetconfig::params::master::server,
  $show_diff                            = $puppetconfig::params::master::show_diff,
  $signeddir                            = $puppetconfig::params::master::signeddir,
  $smtphelo                             = $puppetconfig::params::master::smtphelo,
  $smtpport                             = $puppetconfig::params::master::smtpport,
  $smtpserver                           = $puppetconfig::params::master::smtpserver,
  $splaylimit                           = $puppetconfig::params::master::splaylimit,
  $splay                                = $puppetconfig::params::master::splay,
  $srv_domain                           = $puppetconfig::params::master::srv_domain,
  $ssl_client_ca_auth                   = $puppetconfig::params::master::ssl_client_ca_auth,
  $ssl_client_header                    = $puppetconfig::params::master::ssl_client_header,
  $ssl_client_verify_header             = $puppetconfig::params::master::ssl_client_verify_header,
  $ssldir                               = $puppetconfig::params::master::ssldir,
  $ssl_server_ca_auth                   = $puppetconfig::params::master::ssl_server_ca_auth,
  $statedir                             = $puppetconfig::params::master::statedir,
  $statefile                            = $puppetconfig::params::master::statefile,
  $storeconfigs_backend                 = $puppetconfig::params::master::storeconfigs_backend,
  $storeconfigs                         = $puppetconfig::params::master::storeconfigs,
  $strict_hostname_checking             = $puppetconfig::params::master::strict_hostname_checking,
  $stringify_facts                      = $puppetconfig::params::master::stringify_facts,
  $summarize                            = $puppetconfig::params::master::summarize,
  $syslogfacility                       = $puppetconfig::params::master::syslogfacility,
  $tagmap                               = $puppetconfig::params::master::tagmap,
  $tags                                 = $puppetconfig::params::master::tags,
  $templatedir                          = $puppetconfig::params::master::templatedir,
  $thin_storeconfigs                    = $puppetconfig::params::master::thin_storeconfigs,
  $trace                                = $puppetconfig::params::master::trace,
  $trusted_node_data                    = $puppetconfig::params::master::trusted_node_data,
  $use_cached_catalog                   = $puppetconfig::params::master::use_cached_catalog,
  $usecacheonfailure                    = $puppetconfig::params::master::usecacheonfailure,
  $user                                 = $puppetconfig::params::master::user,
  $use_srv_records                      = $puppetconfig::params::master::use_srv_records,
  $vardir                               = $puppetconfig::params::master::vardir,
  $waitforcert                          = $puppetconfig::params::master::waitforcert,
  $yamldir                              = $puppetconfig::params::master::yamldir,
  $zlib                                 = $puppetconfig::params::master::zlib,
) inherits ::puppetconfig::params::master {
  Ini_setting {
    ensure  => present,
    path    => $config,
    section => $section,
  }
  ini_setting { 'master certname':
    setting => 'certname',
    value   => $certname,
  }
  ini_setting { 'master vardir':
    setting => 'vardir',
    value   => $vardir,
  }
  ini_setting { 'master logdir':
    setting => 'logdir',
    value   => $logdir,
  }
  ini_setting { 'master rundir':
    setting => 'rundir',
    value   => $rundir,
  }
  ini_setting { 'master modulepath':
    setting => 'modulepath',
    value   => $modulepath,
  }
  ini_setting { 'master server':
    setting => 'server',
    value   => $server,
  }
  ini_setting { 'master user':
    setting => 'user',
    value   => $user,
  }
  ini_setting { 'master group':
    setting => 'group',
    value   => $group,
  }
  ini_setting { 'master archive_files':
    setting => 'archive_files',
    value   => $archive_files,
  }
  ini_setting { 'master archive_file_server':
    setting => 'archive_file_server',
    value   => $archive_file_server,
  }
  ini_setting { 'master ca_name':
    setting => 'ca_name',
    value   => $ca_name,
  }
  ini_setting { 'master reports':
    setting => 'reports',
    value   => $reports,
  }
  ini_setting { 'master node_terminus':
    setting => 'node_terminus',
    value   => $node_terminus,
  }
  ini_setting { 'master ssl_client_header':
    setting => 'ssl_client_header',
    value   => $ssl_client_header,
  }
  ini_setting { 'master ssl_client_verify_header':
    setting => 'ssl_client_verify_header',
    value   => $ssl_client_verify_header,
  }
  ini_setting { 'master storeconfigs':
    setting => 'storeconfigs',
    value   => $storeconfigs,
  }
  ini_setting { 'master storeconfigs_backend':
    setting => 'storeconfigs_backend',
    value   => $storeconfigs_backend,
  }
  if $confdir != $::puppetconfig::params::master::confdir {
    ini_setting { 'master confdir':
      setting => 'confdir',
      value   => $confdir,
    }
  }

  if $section != $::puppetconfig::params::master::section {
    ini_setting { 'master section':
      setting => 'name',
      value   => $section,
    }
  }
  if $priority != $::puppetconfig::params::master::priority {
    ini_setting { 'master priority':
      setting => 'priority',
      value   => $priority,
    }
  }
  if $trace != $::puppetconfig::params::master::trace {
    ini_setting { 'master trace':
      setting => 'trace',
      value   => $trace,
    }
  }
  if $profile != $::puppetconfig::params::master::profile {
    ini_setting { 'master profile':
      setting => 'profile',
      value   => $profile,
    }
  }
  if $autoflush != $::puppetconfig::params::master::autoflush {
    ini_setting { 'master autoflush':
      setting => 'autoflush',
      value   => $autoflush,
    }
  }
  if $syslogfacility != $::puppetconfig::params::master::syslogfacility {
    ini_setting { 'master syslogfacility':
      setting => 'syslogfacility',
      value   => $syslogfacility,
    }
  }
  if $statedir != $::puppetconfig::params::master::statedir {
    ini_setting { 'master statedir':
      setting => 'statedir',
      value   => $statedir,
    }
  }
  if $genmanifest != $::puppetconfig::params::master::genmanifest {
    ini_setting { 'master genmanifest':
      setting => 'genmanifest',
      value   => $genmanifest,
    }
  }
  if $configprint != $::puppetconfig::params::master::configprint {
    ini_setting { 'master configprint':
      setting => 'configprint',
      value   => $configprint,
    }
  }
  if $color != $::puppetconfig::params::master::color {
    ini_setting { 'master color':
      setting => 'color',
      value   => $color,
    }
  }
  if $mkusers != $::puppetconfig::params::master::mkusers {
    ini_setting { 'master mkusers':
      setting => 'mkusers',
      value   => $mkusers,
    }
  }
  if $manage_internal_file_permissions != $::puppetconfig::params::master::manage_internal_file_permissions {
    ini_setting { 'master manage_internal_file_permissions':
      setting => 'manage_internal_file_permissions',
      value   => $manage_internal_file_permissions,
    }
  }
  if $onetime != $::puppetconfig::params::master::onetime {
    ini_setting { 'master onetime':
      setting => 'onetime',
      value   => $onetime,
    }
  }
  if $path != $::puppetconfig::params::master::path {
    ini_setting { 'master path':
      setting => 'path',
      value   => $path,
    }
  }
  if $libdir != $::puppetconfig::params::master::libdir {
    ini_setting { 'master libdir':
      setting => 'libdir',
      value   => $libdir,
    }
  }
  if $ignoreimport != $::puppetconfig::params::master::ignoreimport {
    ini_setting { 'master ignoreimport':
      setting => 'ignoreimport',
      value   => $ignoreimport,
    }
  }
  if $environment != $::puppetconfig::params::master::environment {
    ini_setting { 'master environment':
      setting => 'environment',
      value   => $environment,
    }
  }
  if $diff_args != $::puppetconfig::params::master::diff_args {
    ini_setting { 'master diff_args':
      setting => 'diff_args',
      value   => $diff_args,
    }
  }
  if $diff != $::puppetconfig::params::master::diff {
    ini_setting { 'master diff':
      setting => 'diff',
      value   => $diff,
    }
  }
  if $show_diff != $::puppetconfig::params::master::show_diff {
    ini_setting { 'master show_diff':
      setting => 'show_diff',
      value   => $show_diff,
    }
  }
  if $daemonize != $::puppetconfig::params::master::daemonize {
    ini_setting { 'master daemonize':
      setting => 'daemonize',
      value   => $daemonize,
    }
  }
  if $maximum_uid != $::puppetconfig::params::master::maximum_uid {
    ini_setting { 'master maximum_uid':
      setting => 'maximum_uid',
      value   => $maximum_uid,
    }
  }
  if $route_file != $::puppetconfig::params::master::route_file {
    ini_setting { 'master route_file':
      setting => 'route_file',
      value   => $route_file,
    }
  }
  if $node_cache_terminus != $::puppetconfig::params::master::node_cache_terminus {
    ini_setting { 'master node_cache_terminus':
      setting => 'node_cache_terminus',
      value   => $node_cache_terminus,
    }
  }
  if $data_binding_terminus != $::puppetconfig::params::master::data_binding_terminus {
    ini_setting { 'master data_binding_terminus':
      setting => 'data_binding_terminus',
      value   => $data_binding_terminus,
    }
  }
  if $hiera_config != $::puppetconfig::params::master::hiera_config {
    ini_setting { 'master hiera_config':
      setting => 'hiera_config',
      value   => $hiera_config,
    }
  }
  if $binder != $::puppetconfig::params::master::binder {
    ini_setting { 'master binder':
      setting => 'binder',
      value   => $binder,
    }
  }
  if $binder_config != $::puppetconfig::params::master::binder_config {
    ini_setting { 'master binder_config':
      setting => 'binder_config',
      value   => $binder_config,
    }
  }
  if $catalog_terminus != $::puppetconfig::params::master::catalog_terminus {
    ini_setting { 'master catalog_terminus':
      setting => 'catalog_terminus',
      value   => $catalog_terminus,
    }
  }
  if $catalog_cache_terminus != $::puppetconfig::params::master::catalog_cache_terminus {
    ini_setting { 'master catalog_cache_terminus':
      setting => 'catalog_cache_terminus',
      value   => $catalog_cache_terminus,
    }
  }
  if $facts_terminus != $::puppetconfig::params::master::facts_terminus {
    ini_setting { 'master facts_terminus':
      setting => 'facts_terminus',
      value   => $facts_terminus,
    }
  }
  if $inventory_terminus != $::puppetconfig::params::master::inventory_terminus {
    ini_setting { 'master inventory_terminus':
      setting => 'inventory_terminus',
      value   => $inventory_terminus,
    }
  }
  if $default_file_terminus != $::puppetconfig::params::master::default_file_terminus {
    ini_setting { 'master default_file_terminus':
      setting => 'default_file_terminus',
      value   => $default_file_terminus,
    }
  }
  if $httplog != $::puppetconfig::params::master::httplog {
    ini_setting { 'master httplog':
      setting => 'httplog',
      value   => $httplog,
    }
  }
  if $http_proxy_host != $::puppetconfig::params::master::http_proxy_host {
    ini_setting { 'master http_proxy_host':
      setting => 'http_proxy_host',
      value   => $http_proxy_host,
    }
  }
  if $http_proxy_port != $::puppetconfig::params::master::http_proxy_port {
    ini_setting { 'master http_proxy_port':
      setting => 'http_proxy_port',
      value   => $http_proxy_port,
    }
  }
  if $filetimeout != $::puppetconfig::params::master::filetimeout {
    ini_setting { 'master filetimeout':
      setting => 'filetimeout',
      value   => $filetimeout,
    }
  }
  if $queue_type != $::puppetconfig::params::master::queue_type {
    ini_setting { 'master queue_type':
      setting => 'queue_type',
      value   => $queue_type,
    }
  }
  if $queue_source != $::puppetconfig::params::master::queue_source {
    ini_setting { 'master queue_source':
      setting => 'queue_source',
      value   => $queue_source,
    }
  }
  if $async_storeconfigs != $::puppetconfig::params::master::async_storeconfigs {
    ini_setting { 'master async_storeconfigs':
      setting => 'async_storeconfigs',
      value   => $async_storeconfigs,
    }
  }
  if $thin_storeconfigs != $::puppetconfig::params::master::thin_storeconfigs {
    ini_setting { 'master thin_storeconfigs':
      setting => 'thin_storeconfigs',
      value   => $thin_storeconfigs,
    }
  }
  if $config_version != $::puppetconfig::params::master::config_version {
    ini_setting { 'master config_version':
      setting => 'config_version',
      value   => $config_version,
    }
  }
  if $zlib != $::puppetconfig::params::master::zlib {
    ini_setting { 'master zlib':
      setting => 'zlib',
      value   => $zlib,
    }
  }
  if $prerun_command != $::puppetconfig::params::master::prerun_command {
    ini_setting { 'master prerun_command':
      setting => 'prerun_command',
      value   => $prerun_command,
    }
  }
  if $postrun_command != $::puppetconfig::params::master::postrun_command {
    ini_setting { 'master postrun_command':
      setting => 'postrun_command',
      value   => $postrun_command,
    }
  }
  if $freeze_main != $::puppetconfig::params::master::freeze_main {
    ini_setting { 'master freeze_main':
      setting => 'freeze_main',
      value   => $freeze_main,
    }
  }
  if $stringify_facts != $::puppetconfig::params::master::stringify_facts {
    ini_setting { 'master stringify_facts':
      setting => 'stringify_facts',
      value   => $stringify_facts,
    }
  }
  if $trusted_node_data != $::puppetconfig::params::master::trusted_node_data {
    ini_setting { 'master trusted_node_data':
      setting => 'trusted_node_data',
      value   => $trusted_node_data,
    }
  }
  if $certdnsnames != $::puppetconfig::params::master::certdnsnames {
    ini_setting { 'master certdnsnames':
      setting => 'certdnsnames',
      value   => $certdnsnames,
    }
  }
  if $dns_alt_names != $::puppetconfig::params::master::dns_alt_names {
    ini_setting { 'master dns_alt_names':
      setting => 'dns_alt_names',
      value   => $dns_alt_names,
    }
  }
  if $csr_attributes != $::puppetconfig::params::master::csr_attributes {
    ini_setting { 'master csr_attributes':
      setting => 'csr_attributes',
      value   => $csr_attributes,
    }
  }
  if $certdir != $::puppetconfig::params::master::certdir {
    ini_setting { 'master certdir':
      setting => 'certdir',
      value   => $certdir,
    }
  }
  if $ssldir != $::puppetconfig::params::master::ssldir {
    ini_setting { 'master ssldir':
      setting => 'ssldir',
      value   => $ssldir,
    }
  }
  if $publickeydir != $::puppetconfig::params::master::publickeydir {
    ini_setting { 'master publickeydir':
      setting => 'publickeydir',
      value   => $publickeydir,
    }
  }
  if $requestdir != $::puppetconfig::params::master::requestdir {
    ini_setting { 'master requestdir':
      setting => 'requestdir',
      value   => $requestdir,
    }
  }
  if $privatekeydir != $::puppetconfig::params::master::privatekeydir {
    ini_setting { 'master privatekeydir':
      setting => 'privatekeydir',
      value   => $privatekeydir,
    }
  }
  if $privatedir != $::puppetconfig::params::master::privatedir {
    ini_setting { 'master privatedir':
      setting => 'privatedir',
      value   => $privatedir,
    }
  }
  if $passfile != $::puppetconfig::params::master::passfile {
    ini_setting { 'master passfile':
      setting => 'passfile',
      value   => $passfile,
    }
  }
  if $hostcsr != $::puppetconfig::params::master::hostcsr {
    ini_setting { 'master hostcsr':
      setting => 'hostcsr',
      value   => $hostcsr,
    }
  }
  if $hostcert != $::puppetconfig::params::master::hostcert {
    ini_setting { 'master hostcert':
      setting => 'hostcert',
      value   => $hostcert,
    }
  }
  if $hostprivkey != $::puppetconfig::params::master::hostprivkey {
    ini_setting { 'master hostprivkey':
      setting => 'hostprivkey',
      value   => $hostprivkey,
    }
  }
  if $hostpubkey != $::puppetconfig::params::master::hostpubkey {
    ini_setting { 'master hostpubkey':
      setting => 'hostpubkey',
      value   => $hostpubkey,
    }
  }
  if $localcacert != $::puppetconfig::params::master::localcacert {
    ini_setting { 'master localcacert':
      setting => 'localcacert',
      value   => $localcacert,
    }
  }
  if $ssl_client_ca_auth != $::puppetconfig::params::master::ssl_client_ca_auth {
    ini_setting { 'master ssl_client_ca_auth':
      setting => 'ssl_client_ca_auth',
      value   => $ssl_client_ca_auth,
    }
  }
  if $ssl_server_ca_auth != $::puppetconfig::params::master::ssl_server_ca_auth {
    ini_setting { 'master ssl_server_ca_auth':
      setting => 'ssl_server_ca_auth',
      value   => $ssl_server_ca_auth,
    }
  }
  if $hostcrl != $::puppetconfig::params::master::hostcrl {
    ini_setting { 'master hostcrl':
      setting => 'hostcrl',
      value   => $hostcrl,
    }
  }
  if $certificate_revocation != $::puppetconfig::params::master::certificate_revocation {
    ini_setting { 'master certificate_revocation':
      setting => 'certificate_revocation',
      value   => $certificate_revocation,
    }
  }
  if $certificate_expire_warning != $::puppetconfig::params::master::certificate_expire_warning {
    ini_setting { 'master certificate_expire_warning':
      setting => 'certificate_expire_warning',
      value   => $certificate_expire_warning,
    }
  }
  if $plugindest != $::puppetconfig::params::master::plugindest {
    ini_setting { 'master plugindest':
      setting => 'plugindest',
      value   => $plugindest,
    }
  }
  if $pluginsource != $::puppetconfig::params::master::pluginsource {
    ini_setting { 'master pluginsource':
      setting => 'pluginsource',
      value   => $pluginsource,
    }
  }
  if $pluginfactdest != $::puppetconfig::params::master::pluginfactdest {
    ini_setting { 'master pluginfactdest':
      setting => 'pluginfactdest',
      value   => $pluginfactdest,
    }
  }
  if $pluginfactsource != $::puppetconfig::params::master::pluginfactsource {
    ini_setting { 'master pluginfactsource':
      setting => 'pluginfactsource',
      value   => $pluginfactsource,
    }
  }
  if $pluginsync != $::puppetconfig::params::master::pluginsync {
    ini_setting { 'master pluginsync':
      setting => 'pluginsync',
      value   => $pluginsync,
    }
  }
  if $pluginsignore != $::puppetconfig::params::master::pluginsignore {
    ini_setting { 'master pluginsignore':
      setting => 'pluginsignore',
      value   => $pluginsignore,
    }
  }
  if $factpath != $::puppetconfig::params::master::factpath {
    ini_setting { 'master factpath':
      setting => 'factpath',
      value   => $factpath,
    }
  }
  if $external_nodes != $::puppetconfig::params::master::external_nodes {
    ini_setting { 'master external_nodes':
      setting => 'external_nodes',
      value   => $external_nodes,
    }
  }
  if $module_repository != $::puppetconfig::params::master::module_repository {
    ini_setting { 'master module_repository':
      setting => 'module_repository',
      value   => $module_repository,
    }
  }
  if $module_working_dir != $::puppetconfig::params::master::module_working_dir {
    ini_setting { 'master module_working_dir':
      setting => 'module_working_dir',
      value   => $module_working_dir,
    }
  }
  if $module_skeleton_dir != $::puppetconfig::params::master::module_skeleton_dir {
    ini_setting { 'master module_skeleton_dir':
      setting => 'module_skeleton_dir',
      value   => $module_skeleton_dir,
    }
  }
  if $cadir != $::puppetconfig::params::master::cadir {
    ini_setting { 'master cadir':
      setting => 'cadir',
      value   => $cadir,
    }
  }
  if $cacert != $::puppetconfig::params::master::cacert {
    ini_setting { 'master cacert':
      setting => 'cacert',
      value   => $cacert,
    }
  }
  if $cakey != $::puppetconfig::params::master::cakey {
    ini_setting { 'master cakey':
      setting => 'cakey',
      value   => $cakey,
    }
  }
  if $capub != $::puppetconfig::params::master::capub {
    ini_setting { 'master capub':
      setting => 'capub',
      value   => $capub,
    }
  }
  if $cacrl != $::puppetconfig::params::master::cacrl {
    ini_setting { 'master cacrl':
      setting => 'cacrl',
      value   => $cacrl,
    }
  }
  if $caprivatedir != $::puppetconfig::params::master::caprivatedir {
    ini_setting { 'master caprivatedir':
      setting => 'caprivatedir',
      value   => $caprivatedir,
    }
  }
  if $csrdir != $::puppetconfig::params::master::csrdir {
    ini_setting { 'master csrdir':
      setting => 'csrdir',
      value   => $csrdir,
    }
  }
  if $signeddir != $::puppetconfig::params::master::signeddir {
    ini_setting { 'master signeddir':
      setting => 'signeddir',
      value   => $signeddir,
    }
  }
  if $capass != $::puppetconfig::params::master::capass {
    ini_setting { 'master capass':
      setting => 'capass',
      value   => $capass,
    }
  }
  if $serial != $::puppetconfig::params::master::serial {
    ini_setting { 'master serial':
      setting => 'serial',
      value   => $serial,
    }
  }
  if $autosign != $::puppetconfig::params::master::autosign {
    ini_setting { 'master autosign':
      setting => 'autosign',
      value   => $autosign,
    }
  }
  if $allow_duplicate_certs != $::puppetconfig::params::master::allow_duplicate_certs {
    ini_setting { 'master allow_duplicate_certs':
      setting => 'allow_duplicate_certs',
      value   => $allow_duplicate_certs,
    }
  }
  if $ca_ttl != $::puppetconfig::params::master::ca_ttl {
    ini_setting { 'master ca_ttl':
      setting => 'ca_ttl',
      value   => $ca_ttl,
    }
  }
  if $req_bits != $::puppetconfig::params::master::req_bits {
    ini_setting { 'master req_bits':
      setting => 'req_bits',
      value   => $req_bits,
    }
  }
  if $keylength != $::puppetconfig::params::master::keylength {
    ini_setting { 'master keylength':
      setting => 'keylength',
      value   => $keylength,
    }
  }
  if $cert_inventory != $::puppetconfig::params::master::cert_inventory {
    ini_setting { 'master cert_inventory':
      setting => 'cert_inventory',
      value   => $cert_inventory,
    }
  }
  if $config_file_name != $::puppetconfig::params::master::config_file_name {
    ini_setting { 'master config_file_name':
      setting => 'config_file_name',
      value   => $config_file_name,
    }
  }
  if $config != $::puppetconfig::params::master::config {
    ini_setting { 'master config':
      setting => 'config',
      value   => $config,
    }
  }
  if $pidfile != $::puppetconfig::params::master::pidfile {
    ini_setting { 'master pidfile':
      setting => 'pidfile',
      value   => $pidfile,
    }
  }
  if $bindaddress != $::puppetconfig::params::master::bindaddress {
    ini_setting { 'master bindaddress':
      setting => 'bindaddress',
      value   => $bindaddress,
    }
  }
  if $manifestdir != $::puppetconfig::params::master::manifestdir {
    ini_setting { 'master manifestdir':
      setting => 'manifestdir',
      value   => $manifestdir,
    }
  }
  if $manifest != $::puppetconfig::params::master::manifest {
    ini_setting { 'master manifest':
      setting => 'manifest',
      value   => $manifest,
    }
  }
  if $code != $::puppetconfig::params::master::code {
    ini_setting { 'master code':
      setting => 'code',
      value   => $code,
    }
  }
  if $masterlog != $::puppetconfig::params::master::masterlog {
    ini_setting { 'master masterlog':
      setting => 'masterlog',
      value   => $masterlog,
    }
  }
  if $masterhttplog != $::puppetconfig::params::master::masterhttplog {
    ini_setting { 'master masterhttplog':
      setting => 'masterhttplog',
      value   => $masterhttplog,
    }
  }
  if $masterport != $::puppetconfig::params::master::masterport {
    ini_setting { 'master masterport':
      setting => 'masterport',
      value   => $masterport,
    }
  }
  if $node_name != $::puppetconfig::params::master::node_name {
    ini_setting { 'master node_name':
      setting => 'node_name',
      value   => $node_name,
    }
  }
  if $bucketdir != $::puppetconfig::params::master::bucketdir {
    ini_setting { 'master bucketdir':
      setting => 'bucketdir',
      value   => $bucketdir,
    }
  }
  if $rest_authconfig != $::puppetconfig::params::master::rest_authconfig {
    ini_setting { 'master rest_authconfig':
      setting => 'rest_authconfig',
      value   => $rest_authconfig,
    }
  }
  if $ca != $::puppetconfig::params::master::ca {
    ini_setting { 'master ca':
      setting => 'ca',
      value   => $ca,
    }
  }
  if $yamldir != $::puppetconfig::params::master::yamldir {
    ini_setting { 'master yamldir':
      setting => 'yamldir',
      value   => $yamldir,
    }
  }
  if $server_datadir != $::puppetconfig::params::master::server_datadir {
    ini_setting { 'master server_datadir':
      setting => 'server_datadir',
      value   => $server_datadir,
    }
  }
  if $reportdir != $::puppetconfig::params::master::reportdir {
    ini_setting { 'master reportdir':
      setting => 'reportdir',
      value   => $reportdir,
    }
  }
  if $reporturl != $::puppetconfig::params::master::reporturl {
    ini_setting { 'master reporturl':
      setting => 'reporturl',
      value   => $reporturl,
    }
  }
  if $fileserverconfig != $::puppetconfig::params::master::fileserverconfig {
    ini_setting { 'master fileserverconfig':
      setting => 'fileserverconfig',
      value   => $fileserverconfig,
    }
  }
  if $strict_hostname_checking != $::puppetconfig::params::master::strict_hostname_checking {
    ini_setting { 'master strict_hostname_checking':
      setting => 'strict_hostname_checking',
      value   => $strict_hostname_checking,
    }
  }
  if $rrddir != $::puppetconfig::params::master::rrddir {
    ini_setting { 'master rrddir':
      setting => 'rrddir',
      value   => $rrddir,
    }
  }
  if $rrdinterval != $::puppetconfig::params::master::rrdinterval {
    ini_setting { 'master rrdinterval':
      setting => 'rrdinterval',
      value   => $rrdinterval,
    }
  }
  if $devicedir != $::puppetconfig::params::master::devicedir {
    ini_setting { 'master devicedir':
      setting => 'devicedir',
      value   => $devicedir,
    }
  }
  if $deviceconfig != $::puppetconfig::params::master::deviceconfig {
    ini_setting { 'master deviceconfig':
      setting => 'deviceconfig',
      value   => $deviceconfig,
    }
  }
  if $node_name_value != $::puppetconfig::params::master::node_name_value {
    ini_setting { 'master node_name_value':
      setting => 'node_name_value',
      value   => $node_name_value,
    }
  }
  if $node_name_fact != $::puppetconfig::params::master::node_name_fact {
    ini_setting { 'master node_name_fact':
      setting => 'node_name_fact',
      value   => $node_name_fact,
    }
  }
  if $localconfig != $::puppetconfig::params::master::localconfig {
    ini_setting { 'master localconfig':
      setting => 'localconfig',
      value   => $localconfig,
    }
  }
  if $statefile != $::puppetconfig::params::master::statefile {
    ini_setting { 'master statefile':
      setting => 'statefile',
      value   => $statefile,
    }
  }
  if $clientyamldir != $::puppetconfig::params::master::clientyamldir {
    ini_setting { 'master clientyamldir':
      setting => 'clientyamldir',
      value   => $clientyamldir,
    }
  }
  if $client_datadir != $::puppetconfig::params::master::client_datadir {
    ini_setting { 'master client_datadir':
      setting => 'client_datadir',
      value   => $client_datadir,
    }
  }
  if $classfile != $::puppetconfig::params::master::classfile {
    ini_setting { 'master classfile':
      setting => 'classfile',
      value   => $classfile,
    }
  }
  if $resourcefile != $::puppetconfig::params::master::resourcefile {
    ini_setting { 'master resourcefile':
      setting => 'resourcefile',
      value   => $resourcefile,
    }
  }
  if $puppetdlog != $::puppetconfig::params::master::puppetdlog {
    ini_setting { 'master puppetdlog':
      setting => 'puppetdlog',
      value   => $puppetdlog,
    }
  }
  if $use_srv_records != $::puppetconfig::params::master::use_srv_records {
    ini_setting { 'master use_srv_records':
      setting => 'use_srv_records',
      value   => $use_srv_records,
    }
  }
  if $srv_domain != $::puppetconfig::params::master::srv_domain {
    ini_setting { 'master srv_domain':
      setting => 'srv_domain',
      value   => $srv_domain,
    }
  }
  if $ignoreschedules != $::puppetconfig::params::master::ignoreschedules {
    ini_setting { 'master ignoreschedules':
      setting => 'ignoreschedules',
      value   => $ignoreschedules,
    }
  }
  if $default_schedules != $::puppetconfig::params::master::default_schedules {
    ini_setting { 'master default_schedules':
      setting => 'default_schedules',
      value   => $default_schedules,
    }
  }
  if $puppetport != $::puppetconfig::params::master::puppetport {
    ini_setting { 'master puppetport':
      setting => 'puppetport',
      value   => $puppetport,
    }
  }
  if $noop != $::puppetconfig::params::master::noop {
    ini_setting { 'master noop':
      setting => 'noop',
      value   => $noop,
    }
  }
  if $runinterval != $::puppetconfig::params::master::runinterval {
    ini_setting { 'master runinterval':
      setting => 'runinterval',
      value   => $runinterval,
    }
  }
  if $listen != $::puppetconfig::params::master::listen {
    ini_setting { 'master listen':
      setting => 'listen',
      value   => $listen,
    }
  }
  if $ca_server != $::puppetconfig::params::master::ca_server {
    ini_setting { 'master ca_server':
      setting => 'ca_server',
      value   => $ca_server,
    }
  }
  if $ca_port != $::puppetconfig::params::master::ca_port {
    ini_setting { 'master ca_port':
      setting => 'ca_port',
      value   => $ca_port,
    }
  }
  if $catalog_format != $::puppetconfig::params::master::catalog_format {
    ini_setting { 'master catalog_format':
      setting => 'catalog_format',
      value   => $catalog_format,
    }
  }
  if $preferred_serialization_format != $::puppetconfig::params::master::preferred_serialization_format {
    ini_setting { 'master preferred_serialization_format':
      setting => 'preferred_serialization_format',
      value   => $preferred_serialization_format,
    }
  }
  if $report_serialization_format != $::puppetconfig::params::master::report_serialization_format {
    ini_setting { 'master report_serialization_format':
      setting => 'report_serialization_format',
      value   => $report_serialization_format,
    }
  }
  if $legacy_query_parameter_serialization != $::puppetconfig::params::master::legacy_query_parameter_serialization {
    ini_setting { 'master legacy_query_parameter_serialization':
      setting => 'legacy_query_parameter_serialization',
      value   => $legacy_query_parameter_serialization,
    }
  }
  if $agent_catalog_run_lockfile != $::puppetconfig::params::master::agent_catalog_run_lockfile {
    ini_setting { 'master agent_catalog_run_lockfile':
      setting => 'agent_catalog_run_lockfile',
      value   => $agent_catalog_run_lockfile,
    }
  }
  if $agent_disabled_lockfile != $::puppetconfig::params::master::agent_disabled_lockfile {
    ini_setting { 'master agent_disabled_lockfile':
      setting => 'agent_disabled_lockfile',
      value   => $agent_disabled_lockfile,
    }
  }
  if $usecacheonfailure != $::puppetconfig::params::master::usecacheonfailure {
    ini_setting { 'master usecacheonfailure':
      setting => 'usecacheonfailure',
      value   => $usecacheonfailure,
    }
  }
  if $use_cached_catalog != $::puppetconfig::params::master::use_cached_catalog {
    ini_setting { 'master use_cached_catalog':
      setting => 'use_cached_catalog',
      value   => $use_cached_catalog,
    }
  }
  if $ignoremissingtypes != $::puppetconfig::params::master::ignoremissingtypes {
    ini_setting { 'master ignoremissingtypes':
      setting => 'ignoremissingtypes',
      value   => $ignoremissingtypes,
    }
  }
  if $ignorecache != $::puppetconfig::params::master::ignorecache {
    ini_setting { 'master ignorecache':
      setting => 'ignorecache',
      value   => $ignorecache,
    }
  }
  if $dynamicfacts != $::puppetconfig::params::master::dynamicfacts {
    ini_setting { 'master dynamicfacts':
      setting => 'dynamicfacts',
      value   => $dynamicfacts,
    }
  }
  if $splaylimit != $::puppetconfig::params::master::splaylimit {
    ini_setting { 'master splaylimit':
      setting => 'splaylimit',
      value   => $splaylimit,
    }
  }
  if $splay != $::puppetconfig::params::master::splay {
    ini_setting { 'master splay':
      setting => 'splay',
      value   => $splay,
    }
  }
  if $clientbucketdir != $::puppetconfig::params::master::clientbucketdir {
    ini_setting { 'master clientbucketdir':
      setting => 'clientbucketdir',
      value   => $clientbucketdir,
    }
  }
  if $configtimeout != $::puppetconfig::params::master::configtimeout {
    ini_setting { 'master configtimeout':
      setting => 'configtimeout',
      value   => $configtimeout,
    }
  }
  if $report_server != $::puppetconfig::params::master::report_server {
    ini_setting { 'master report_server':
      setting => 'report_server',
      value   => $report_server,
    }
  }
  if $report_port != $::puppetconfig::params::master::report_port {
    ini_setting { 'master report_port':
      setting => 'report_port',
      value   => $report_port,
    }
  }
  if $inventory_server != $::puppetconfig::params::master::inventory_server {
    ini_setting { 'master inventory_server':
      setting => 'inventory_server',
      value   => $inventory_server,
    }
  }
  if $inventory_port != $::puppetconfig::params::master::inventory_port {
    ini_setting { 'master inventory_port':
      setting => 'inventory_port',
      value   => $inventory_port,
    }
  }
  if $report != $::puppetconfig::params::master::report {
    ini_setting { 'master report':
      setting => 'report',
      value   => $report,
    }
  }
  if $lastrunfile != $::puppetconfig::params::master::lastrunfile {
    ini_setting { 'master lastrunfile':
      setting => 'lastrunfile',
      value   => $lastrunfile,
    }
  }
  if $lastrunreport != $::puppetconfig::params::master::lastrunreport {
    ini_setting { 'master lastrunreport':
      setting => 'lastrunreport',
      value   => $lastrunreport,
    }
  }
  if $graph != $::puppetconfig::params::master::graph {
    ini_setting { 'master graph':
      setting => 'graph',
      value   => $graph,
    }
  }
  if $graphdir != $::puppetconfig::params::master::graphdir {
    ini_setting { 'master graphdir':
      setting => 'graphdir',
      value   => $graphdir,
    }
  }
  if $http_compression != $::puppetconfig::params::master::http_compression {
    ini_setting { 'master http_compression':
      setting => 'http_compression',
      value   => $http_compression,
    }
  }
  if $waitforcert != $::puppetconfig::params::master::waitforcert {
    ini_setting { 'master waitforcert':
      setting => 'waitforcert',
      value   => $waitforcert,
    }
  }
  if $ordering != $::puppetconfig::params::master::ordering {
    ini_setting { 'master ordering':
      setting => 'ordering',
      value   => $ordering,
    }
  }
  if $tagmap != $::puppetconfig::params::master::tagmap {
    ini_setting { 'master tagmap':
      setting => 'tagmap',
      value   => $tagmap,
    }
  }
  if $sendmail != $::puppetconfig::params::master::sendmail {
    ini_setting { 'master sendmail':
      setting => 'sendmail',
      value   => $sendmail,
    }
  }
  if $reportfrom != $::puppetconfig::params::master::reportfrom {
    ini_setting { 'master reportfrom':
      setting => 'reportfrom',
      value   => $reportfrom,
    }
  }
  if $smtpserver != $::puppetconfig::params::master::smtpserver {
    ini_setting { 'master smtpserver':
      setting => 'smtpserver',
      value   => $smtpserver,
    }
  }
  if $smtpport != $::puppetconfig::params::master::smtpport {
    ini_setting { 'master smtpport':
      setting => 'smtpport',
      value   => $smtpport,
    }
  }
  if $smtphelo != $::puppetconfig::params::master::smtphelo {
    ini_setting { 'master smtphelo':
      setting => 'smtphelo',
      value   => $smtphelo,
    }
  }
  if $dblocation != $::puppetconfig::params::master::dblocation {
    ini_setting { 'master dblocation':
      setting => 'dblocation',
      value   => $dblocation,
    }
  }
  if $dbadapter != $::puppetconfig::params::master::dbadapter {
    ini_setting { 'master dbadapter':
      setting => 'dbadapter',
      value   => $dbadapter,
    }
  }
  if $dbmigrate != $::puppetconfig::params::master::dbmigrate {
    ini_setting { 'master dbmigrate':
      setting => 'dbmigrate',
      value   => $dbmigrate,
    }
  }
  if $dbname != $::puppetconfig::params::master::dbname {
    ini_setting { 'master dbname':
      setting => 'dbname',
      value   => $dbname,
    }
  }
  if $dbserver != $::puppetconfig::params::master::dbserver {
    ini_setting { 'master dbserver':
      setting => 'dbserver',
      value   => $dbserver,
    }
  }
  if $dbport != $::puppetconfig::params::master::dbport {
    ini_setting { 'master dbport':
      setting => 'dbport',
      value   => $dbport,
    }
  }
  if $dbuser != $::puppetconfig::params::master::dbuser {
    ini_setting { 'master dbuser':
      setting => 'dbuser',
      value   => $dbuser,
    }
  }
  if $dbpassword != $::puppetconfig::params::master::dbpassword {
    ini_setting { 'master dbpassword':
      setting => 'dbpassword',
      value   => $dbpassword,
    }
  }
  if $dbconnections != $::puppetconfig::params::master::dbconnections {
    ini_setting { 'master dbconnections':
      setting => 'dbconnections',
      value   => $dbconnections,
    }
  }
  if $dbsocket != $::puppetconfig::params::master::dbsocket {
    ini_setting { 'master dbsocket':
      setting => 'dbsocket',
      value   => $dbsocket,
    }
  }
  if $railslog != $::puppetconfig::params::master::railslog {
    ini_setting { 'master railslog':
      setting => 'railslog',
      value   => $railslog,
    }
  }
  if $rails_loglevel != $::puppetconfig::params::master::rails_loglevel {
    ini_setting { 'master rails_loglevel':
      setting => 'rails_loglevel',
      value   => $rails_loglevel,
    }
  }
  if $couchdb_url != $::puppetconfig::params::master::couchdb_url {
    ini_setting { 'master couchdb_url':
      setting => 'couchdb_url',
      value   => $couchdb_url,
    }
  }
  if $tags != $::puppetconfig::params::master::tags {
    ini_setting { 'master tags':
      setting => 'tags',
      value   => $tags,
    }
  }
  if $evaltrace != $::puppetconfig::params::master::evaltrace {
    ini_setting { 'master evaltrace':
      setting => 'evaltrace',
      value   => $evaltrace,
    }
  }
  if $summarize != $::puppetconfig::params::master::summarize {
    ini_setting { 'master summarize':
      setting => 'summarize',
      value   => $summarize,
    }
  }
  if $ldapssl != $::puppetconfig::params::master::ldapssl {
    ini_setting { 'master ldapssl':
      setting => 'ldapssl',
      value   => $ldapssl,
    }
  }
  if $ldaptls != $::puppetconfig::params::master::ldaptls {
    ini_setting { 'master ldaptls':
      setting => 'ldaptls',
      value   => $ldaptls,
    }
  }
  if $ldapserver != $::puppetconfig::params::master::ldapserver {
    ini_setting { 'master ldapserver':
      setting => 'ldapserver',
      value   => $ldapserver,
    }
  }
  if $ldapport != $::puppetconfig::params::master::ldapport {
    ini_setting { 'master ldapport':
      setting => 'ldapport',
      value   => $ldapport,
    }
  }
  if $ldapstring != $::puppetconfig::params::master::ldapstring {
    ini_setting { 'master ldapstring':
      setting => 'ldapstring',
      value   => $ldapstring,
    }
  }
  if $ldapclassattrs != $::puppetconfig::params::master::ldapclassattrs {
    ini_setting { 'master ldapclassattrs':
      setting => 'ldapclassattrs',
      value   => $ldapclassattrs,
    }
  }
  if $ldapstackedattrs != $::puppetconfig::params::master::ldapstackedattrs {
    ini_setting { 'master ldapstackedattrs':
      setting => 'ldapstackedattrs',
      value   => $ldapstackedattrs,
    }
  }
  if $ldapattrs != $::puppetconfig::params::master::ldapattrs {
    ini_setting { 'master ldapattrs':
      setting => 'ldapattrs',
      value   => $ldapattrs,
    }
  }
  if $ldapparentattr != $::puppetconfig::params::master::ldapparentattr {
    ini_setting { 'master ldapparentattr':
      setting => 'ldapparentattr',
      value   => $ldapparentattr,
    }
  }
  if $ldapuser != $::puppetconfig::params::master::ldapuser {
    ini_setting { 'master ldapuser':
      setting => 'ldapuser',
      value   => $ldapuser,
    }
  }
  if $ldappassword != $::puppetconfig::params::master::ldappassword {
    ini_setting { 'master ldappassword':
      setting => 'ldappassword',
      value   => $ldappassword,
    }
  }
  if $ldapbase != $::puppetconfig::params::master::ldapbase {
    ini_setting { 'master ldapbase':
      setting => 'ldapbase',
      value   => $ldapbase,
    }
  }
  if $templatedir != $::puppetconfig::params::master::templatedir {
    ini_setting { 'master templatedir':
      setting => 'templatedir',
      value   => $templatedir,
    }
  }
  if $allow_variables_with_dashes != $::puppetconfig::params::master::allow_variables_with_dashes {
    ini_setting { 'master allow_variables_with_dashes':
      setting => 'allow_variables_with_dashes',
      value   => $allow_variables_with_dashes,
    }
  }
  if $parser != $::puppetconfig::params::master::parser {
    ini_setting { 'master parser':
      setting => 'parser',
      value   => $parser,
    }
  }
  if $max_errors != $::puppetconfig::params::master::max_errors {
    ini_setting { 'master max_errors':
      setting => 'max_errors',
      value   => $max_errors,
    }
  }
  if $max_warnings != $::puppetconfig::params::master::max_warnings {
    ini_setting { 'master max_warnings':
      setting => 'max_warnings',
      value   => $max_warnings,
    }
  }
  if $max_deprecations != $::puppetconfig::params::master::max_deprecations {
    ini_setting { 'master max_deprecations':
      setting => 'max_deprecations',
      value   => $max_deprecations,
    }
  }
  if $document_all != $::puppetconfig::params::master::document_all {
    ini_setting { 'master document_all':
      setting => 'document_all',
      value   => $document_all,
    }
  }
}
