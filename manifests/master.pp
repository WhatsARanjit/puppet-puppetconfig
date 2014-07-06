class puppet::master (
  $agent_catalog_run_lockfile           = $puppet::params::master::agent_catalog_run_lockfile,
  $agent_disabled_lockfile              = $puppet::params::master::agent_disabled_lockfile,
  $allow_duplicate_certs                = $puppet::params::master::allow_duplicate_certs,
  $allow_variables_with_dashes          = $puppet::params::master::allow_variables_with_dashes,
  $archive_file_server                  = $puppet::params::master::archive_file_server,
  $archive_files                        = $puppet::params::master::archive_files,
  $async_storeconfigs                   = $puppet::params::master::async_storeconfigs,
  $autoflush                            = $puppet::params::master::autoflush,
  $autosign                             = $puppet::params::master::autosign,
  $bindaddress                          = $puppet::params::master::bindaddress,
  $binder_config                        = $puppet::params::master::binder_config,
  $binder                               = $puppet::params::master::binder,
  $bucketdir                            = $puppet::params::master::bucketdir,
  $cacert                               = $puppet::params::master::cacert,
  $cacrl                                = $puppet::params::master::cacrl,
  $cadir                                = $puppet::params::master::cadir,
  $cakey                                = $puppet::params::master::cakey,
  $ca_name                              = $puppet::params::master::ca_name,
  $capass                               = $puppet::params::master::capass,
  $ca_port                              = $puppet::params::master::ca_port,
  $caprivatedir                         = $puppet::params::master::caprivatedir,
  $capub                                = $puppet::params::master::capub,
  $ca                                   = $puppet::params::master::ca,
  $ca_server                            = $puppet::params::master::ca_server,
  $catalog_cache_terminus               = $puppet::params::master::catalog_cache_terminus,
  $catalog_format                       = $puppet::params::master::catalog_format,
  $catalog_terminus                     = $puppet::params::master::catalog_terminus,
  $ca_ttl                               = $puppet::params::master::ca_ttl,
  $certdir                              = $puppet::params::master::certdir,
  $certdnsnames                         = $puppet::params::master::certdnsnames,
  $certificate_expire_warning           = $puppet::params::master::certificate_expire_warning,
  $certificate_revocation               = $puppet::params::master::certificate_revocation,
  $cert_inventory                       = $puppet::params::master::cert_inventory,
  $certname                             = $puppet::params::master::certname,
  $classfile                            = $puppet::params::master::classfile,
  $clientbucketdir                      = $puppet::params::master::clientbucketdir,
  $client_datadir                       = $puppet::params::master::client_datadir,
  $clientyamldir                        = $puppet::params::master::clientyamldir,
  $code                                 = $puppet::params::master::code,
  $color                                = $puppet::params::master::color,
  $confdir                              = $puppet::params::master::confdir,
  $config_file_name                     = $puppet::params::master::config_file_name,
  $configprint                          = $puppet::params::master::configprint,
  $config                               = $puppet::params::master::config,
  $configtimeout                        = $puppet::params::master::configtimeout,
  $config_version                       = $puppet::params::master::config_version,
  $couchdb_url                          = $puppet::params::master::couchdb_url,
  $csr_attributes                       = $puppet::params::master::csr_attributes,
  $csrdir                               = $puppet::params::master::csrdir,
  $daemonize                            = $puppet::params::master::daemonize,
  $data_binding_terminus                = $puppet::params::master::data_binding_terminus,
  $dbadapter                            = $puppet::params::master::dbadapter,
  $dbconnections                        = $puppet::params::master::dbconnections,
  $dblocation                           = $puppet::params::master::dblocation,
  $dbmigrate                            = $puppet::params::master::dbmigrate,
  $dbname                               = $puppet::params::master::dbname,
  $dbpassword                           = $puppet::params::master::dbpassword,
  $dbport                               = $puppet::params::master::dbport,
  $dbserver                             = $puppet::params::master::dbserver,
  $dbsocket                             = $puppet::params::master::dbsocket,
  $dbuser                               = $puppet::params::master::dbuser,
  $default_file_terminus                = $puppet::params::master::default_file_terminus,
  $default_schedules                    = $puppet::params::master::default_schedules,
  $deviceconfig                         = $puppet::params::master::deviceconfig,
  $devicedir                            = $puppet::params::master::devicedir,
  $diff_args                            = $puppet::params::master::diff_args,
  $diff                                 = $puppet::params::master::diff,
  $dns_alt_names                        = $puppet::params::master::dns_alt_names,
  $document_all                         = $puppet::params::master::document_all,
  $dynamicfacts                         = $puppet::params::master::dynamicfacts,
  $environment                          = $puppet::params::master::environment,
  $evaltrace                            = $puppet::params::master::evaltrace,
  $external_nodes                       = $puppet::params::master::external_nodes,
  $factpath                             = $puppet::params::master::factpath,
  $facts_terminus                       = $puppet::params::master::facts_terminus,
  $fileserverconfig                     = $puppet::params::master::fileserverconfig,
  $filetimeout                          = $puppet::params::master::filetimeout,
  $freeze_main                          = $puppet::params::master::freeze_main,
  $genmanifest                          = $puppet::params::master::genmanifest,
  $graphdir                             = $puppet::params::master::graphdir,
  $graph                                = $puppet::params::master::graph,
  $group                                = $puppet::params::master::group,
  $hiera_config                         = $puppet::params::master::hiera_config,
  $hostcert                             = $puppet::params::master::hostcert,
  $hostcrl                              = $puppet::params::master::hostcrl,
  $hostcsr                              = $puppet::params::master::hostcsr,
  $hostprivkey                          = $puppet::params::master::hostprivkey,
  $hostpubkey                           = $puppet::params::master::hostpubkey,
  $http_compression                     = $puppet::params::master::http_compression,
  $httplog                              = $puppet::params::master::httplog,
  $http_proxy_host                      = $puppet::params::master::http_proxy_host,
  $http_proxy_port                      = $puppet::params::master::http_proxy_port,
  $ignorecache                          = $puppet::params::master::ignorecache,
  $ignoreimport                         = $puppet::params::master::ignoreimport,
  $ignoremissingtypes                   = $puppet::params::master::ignoremissingtypes,
  $ignoreschedules                      = $puppet::params::master::ignoreschedules,
  $inventory_port                       = $puppet::params::master::inventory_port,
  $inventory_server                     = $puppet::params::master::inventory_server,
  $inventory_terminus                   = $puppet::params::master::inventory_terminus,
  $keylength                            = $puppet::params::master::keylength,
  $lastrunfile                          = $puppet::params::master::lastrunfile,
  $lastrunreport                        = $puppet::params::master::lastrunreport,
  $ldapattrs                            = $puppet::params::master::ldapattrs,
  $ldapbase                             = $puppet::params::master::ldapbase,
  $ldapclassattrs                       = $puppet::params::master::ldapclassattrs,
  $ldapparentattr                       = $puppet::params::master::ldapparentattr,
  $ldappassword                         = $puppet::params::master::ldappassword,
  $ldapport                             = $puppet::params::master::ldapport,
  $ldapserver                           = $puppet::params::master::ldapserver,
  $ldapssl                              = $puppet::params::master::ldapssl,
  $ldapstackedattrs                     = $puppet::params::master::ldapstackedattrs,
  $ldapstring                           = $puppet::params::master::ldapstring,
  $ldaptls                              = $puppet::params::master::ldaptls,
  $ldapuser                             = $puppet::params::master::ldapuser,
  $legacy_query_parameter_serialization = $puppet::params::master::legacy_query_parameter_serialization,
  $libdir                               = $puppet::params::master::libdir,
  $listen                               = $puppet::params::master::listen,
  $localcacert                          = $puppet::params::master::localcacert,
  $localconfig                          = $puppet::params::master::localconfig,
  $logdir                               = $puppet::params::master::logdir,
  $manage_internal_file_permissions     = $puppet::params::master::manage_internal_file_permissions,
  $manifestdir                          = $puppet::params::master::manifestdir,
  $manifest                             = $puppet::params::master::manifest,
  $masterhttplog                        = $puppet::params::master::masterhttplog,
  $masterlog                            = $puppet::params::master::masterlog,
  $masterport                           = $puppet::params::master::masterport,
  $max_deprecations                     = $puppet::params::master::max_deprecations,
  $max_errors                           = $puppet::params::master::max_errors,
  $maximum_uid                          = $puppet::params::master::maximum_uid,
  $max_warnings                         = $puppet::params::master::max_warnings,
  $mkusers                              = $puppet::params::master::mkusers,
  $modulepath                           = $puppet::params::master::modulepath,
  $module_repository                    = $puppet::params::master::module_repository,
  $module_skeleton_dir                  = $puppet::params::master::module_skeleton_dir,
  $module_working_dir                   = $puppet::params::master::module_working_dir,
  $node_cache_terminus                  = $puppet::params::master::node_cache_terminus,
  $node_name_fact                       = $puppet::params::master::node_name_fact,
  $node_name                            = $puppet::params::master::node_name,
  $node_name_value                      = $puppet::params::master::node_name_value,
  $node_terminus                        = $puppet::params::master::node_terminus,
  $no_op                                = $puppet::params::master::no_op,
  $onetime                              = $puppet::params::master::onetime,
  $ordering                             = $puppet::params::master::ordering,
  $parser                               = $puppet::params::master::parser,
  $passfile                             = $puppet::params::master::passfile,
  $path                                 = $puppet::params::master::path,
  $pidfile                              = $puppet::params::master::pidfile,
  $plugindest                           = $puppet::params::master::plugindest,
  $pluginfactdest                       = $puppet::params::master::pluginfactdest,
  $pluginfactsource                     = $puppet::params::master::pluginfactsource,
  $pluginsignore                        = $puppet::params::master::pluginsignore,
  $pluginsource                         = $puppet::params::master::pluginsource,
  $pluginsync                           = $puppet::params::master::pluginsync,
  $postrun_command                      = $puppet::params::master::postrun_command,
  $preferred_serialization_format       = $puppet::params::master::preferred_serialization_format,
  $prerun_command                       = $puppet::params::master::prerun_command,
  $priority                             = $puppet::params::master::priority,
  $privatedir                           = $puppet::params::master::privatedir,
  $privatekeydir                        = $puppet::params::master::privatekeydir,
  $profile                              = $puppet::params::master::profile,
  $publickeydir                         = $puppet::params::master::publickeydir,
  $puppetdlog                           = $puppet::params::master::puppetdlog,
  $puppetport                           = $puppet::params::master::puppetport,
  $queue_source                         = $puppet::params::master::queue_source,
  $queue_type                           = $puppet::params::master::queue_type,
  $rails_loglevel                       = $puppet::params::master::rails_loglevel,
  $railslog                             = $puppet::params::master::railslog,
  $reportdir                            = $puppet::params::master::reportdir,
  $reportfrom                           = $puppet::params::master::reportfrom,
  $report_port                          = $puppet::params::master::report_port,
  $report                               = $puppet::params::master::report,
  $report_serialization_format          = $puppet::params::master::report_serialization_format,
  $report_server                        = $puppet::params::master::report_server,
  $reports                              = $puppet::params::master::reports,
  $reporturl                            = $puppet::params::master::reporturl,
  $req_bits                             = $puppet::params::master::req_bits,
  $requestdir                           = $puppet::params::master::requestdir,
  $resourcefile                         = $puppet::params::master::resourcefile,
  $rest_authconfig                      = $puppet::params::master::rest_authconfig,
  $route_file                           = $puppet::params::master::route_file,
  $rrddir                               = $puppet::params::master::rrddir,
  $rrdinterval                          = $puppet::params::master::rrdinterval,
  $rundir                               = $puppet::params::master::rundir,
  $runinterval                          = $puppet::params::master::runinterval,
  $section                              = $puppet::params::master::section,
  $sendmail                             = $puppet::params::master::sendmail,
  $serial                               = $puppet::params::master::serial,
  $server_datadir                       = $puppet::params::master::server_datadir,
  $server                               = $puppet::params::master::server,
  $show_diff                            = $puppet::params::master::show_diff,
  $signeddir                            = $puppet::params::master::signeddir,
  $smtphelo                             = $puppet::params::master::smtphelo,
  $smtpport                             = $puppet::params::master::smtpport,
  $smtpserver                           = $puppet::params::master::smtpserver,
  $splaylimit                           = $puppet::params::master::splaylimit,
  $splay                                = $puppet::params::master::splay,
  $srv_domain                           = $puppet::params::master::srv_domain,
  $ssl_client_ca_auth                   = $puppet::params::master::ssl_client_ca_auth,
  $ssl_client_header                    = $puppet::params::master::ssl_client_header,
  $ssl_client_verify_header             = $puppet::params::master::ssl_client_verify_header,
  $ssldir                               = $puppet::params::master::ssldir,
  $ssl_server_ca_auth                   = $puppet::params::master::ssl_server_ca_auth,
  $statedir                             = $puppet::params::master::statedir,
  $statefile                            = $puppet::params::master::statefile,
  $storeconfigs_backend                 = $puppet::params::master::storeconfigs_backend,
  $storeconfigs                         = $puppet::params::master::storeconfigs,
  $strict_hostname_checking             = $puppet::params::master::strict_hostname_checking,
  $stringify_facts                      = $puppet::params::master::stringify_facts,
  $summarize                            = $puppet::params::master::summarize,
  $syslogfacility                       = $puppet::params::master::syslogfacility,
  $tagmap                               = $puppet::params::master::tagmap,
  $tags                                 = $puppet::params::master::tags,
  $templatedir                          = $puppet::params::master::templatedir,
  $thin_storeconfigs                    = $puppet::params::master::thin_storeconfigs,
  $trace                                = $puppet::params::master::trace,
  $trusted_node_data                    = $puppet::params::master::trusted_node_data,
  $use_cached_catalog                   = $puppet::params::master::use_cached_catalog,
  $usecacheonfailure                    = $puppet::params::master::usecacheonfailure,
  $user                                 = $puppet::params::master::user,
  $use_srv_records                      = $puppet::params::master::use_srv_records,
  $vardir                               = $puppet::params::master::vardir,
  $waitforcert                          = $puppet::params::master::waitforcert,
  $yamldir                              = $puppet::params::master::yamldir,
  $zlib                                 = $puppet::params::master::zlib,
) inherits ::puppet::params::master {
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
  if $confdir != $::puppet::params::master::confdir {
    ini_setting { 'master confdir':
      setting => 'confdir',
      value   => $confdir,
    }
  }

  if $section != $::puppet::params::master::section {
    ini_setting { 'master section':
      setting => 'name',
      value   => $section,
    }
  }
  if $priority != $::puppet::params::master::priority {
    ini_setting { 'master priority':
      setting => 'priority',
      value   => $priority,
    }
  }
  if $trace != $::puppet::params::master::trace {
    ini_setting { 'master trace':
      setting => 'trace',
      value   => $trace,
    }
  }
  if $profile != $::puppet::params::master::profile {
    ini_setting { 'master profile':
      setting => 'profile',
      value   => $profile,
    }
  }
  if $autoflush != $::puppet::params::master::autoflush {
    ini_setting { 'master autoflush':
      setting => 'autoflush',
      value   => $autoflush,
    }
  }
  if $syslogfacility != $::puppet::params::master::syslogfacility {
    ini_setting { 'master syslogfacility':
      setting => 'syslogfacility',
      value   => $syslogfacility,
    }
  }
  if $statedir != $::puppet::params::master::statedir {
    ini_setting { 'master statedir':
      setting => 'statedir',
      value   => $statedir,
    }
  }
  if $genmanifest != $::puppet::params::master::genmanifest {
    ini_setting { 'master genmanifest':
      setting => 'genmanifest',
      value   => $genmanifest,
    }
  }
  if $configprint != $::puppet::params::master::configprint {
    ini_setting { 'master configprint':
      setting => 'configprint',
      value   => $configprint,
    }
  }
  if $color != $::puppet::params::master::color {
    ini_setting { 'master color':
      setting => 'color',
      value   => $color,
    }
  }
  if $mkusers != $::puppet::params::master::mkusers {
    ini_setting { 'master mkusers':
      setting => 'mkusers',
      value   => $mkusers,
    }
  }
  if $manage_internal_file_permissions != $::puppet::params::master::manage_internal_file_permissions {
    ini_setting { 'master manage_internal_file_permissions':
      setting => 'manage_internal_file_permissions',
      value   => $manage_internal_file_permissions,
    }
  }
  if $onetime != $::puppet::params::master::onetime {
    ini_setting { 'master onetime':
      setting => 'onetime',
      value   => $onetime,
    }
  }
  if $path != $::puppet::params::master::path {
    ini_setting { 'master path':
      setting => 'path',
      value   => $path,
    }
  }
  if $libdir != $::puppet::params::master::libdir {
    ini_setting { 'master libdir':
      setting => 'libdir',
      value   => $libdir,
    }
  }
  if $ignoreimport != $::puppet::params::master::ignoreimport {
    ini_setting { 'master ignoreimport':
      setting => 'ignoreimport',
      value   => $ignoreimport,
    }
  }
  if $environment != $::puppet::params::master::environment {
    ini_setting { 'master environment':
      setting => 'environment',
      value   => $environment,
    }
  }
  if $diff_args != $::puppet::params::master::diff_args {
    ini_setting { 'master diff_args':
      setting => 'diff_args',
      value   => $diff_args,
    }
  }
  if $diff != $::puppet::params::master::diff {
    ini_setting { 'master diff':
      setting => 'diff',
      value   => $diff,
    }
  }
  if $show_diff != $::puppet::params::master::show_diff {
    ini_setting { 'master show_diff':
      setting => 'show_diff',
      value   => $show_diff,
    }
  }
  if $daemonize != $::puppet::params::master::daemonize {
    ini_setting { 'master daemonize':
      setting => 'daemonize',
      value   => $daemonize,
    }
  }
  if $maximum_uid != $::puppet::params::master::maximum_uid {
    ini_setting { 'master maximum_uid':
      setting => 'maximum_uid',
      value   => $maximum_uid,
    }
  }
  if $route_file != $::puppet::params::master::route_file {
    ini_setting { 'master route_file':
      setting => 'route_file',
      value   => $route_file,
    }
  }
  if $node_cache_terminus != $::puppet::params::master::node_cache_terminus {
    ini_setting { 'master node_cache_terminus':
      setting => 'node_cache_terminus',
      value   => $node_cache_terminus,
    }
  }
  if $data_binding_terminus != $::puppet::params::master::data_binding_terminus {
    ini_setting { 'master data_binding_terminus':
      setting => 'data_binding_terminus',
      value   => $data_binding_terminus,
    }
  }
  if $hiera_config != $::puppet::params::master::hiera_config {
    ini_setting { 'master hiera_config':
      setting => 'hiera_config',
      value   => $hiera_config,
    }
  }
  if $binder != $::puppet::params::master::binder {
    ini_setting { 'master binder':
      setting => 'binder',
      value   => $binder,
    }
  }
  if $binder_config != $::puppet::params::master::binder_config {
    ini_setting { 'master binder_config':
      setting => 'binder_config',
      value   => $binder_config,
    }
  }
  if $catalog_terminus != $::puppet::params::master::catalog_terminus {
    ini_setting { 'master catalog_terminus':
      setting => 'catalog_terminus',
      value   => $catalog_terminus,
    }
  }
  if $catalog_cache_terminus != $::puppet::params::master::catalog_cache_terminus {
    ini_setting { 'master catalog_cache_terminus':
      setting => 'catalog_cache_terminus',
      value   => $catalog_cache_terminus,
    }
  }
  if $facts_terminus != $::puppet::params::master::facts_terminus {
    ini_setting { 'master facts_terminus':
      setting => 'facts_terminus',
      value   => $facts_terminus,
    }
  }
  if $inventory_terminus != $::puppet::params::master::inventory_terminus {
    ini_setting { 'master inventory_terminus':
      setting => 'inventory_terminus',
      value   => $inventory_terminus,
    }
  }
  if $default_file_terminus != $::puppet::params::master::default_file_terminus {
    ini_setting { 'master default_file_terminus':
      setting => 'default_file_terminus',
      value   => $default_file_terminus,
    }
  }
  if $httplog != $::puppet::params::master::httplog {
    ini_setting { 'master httplog':
      setting => 'httplog',
      value   => $httplog,
    }
  }
  if $http_proxy_host != $::puppet::params::master::http_proxy_host {
    ini_setting { 'master http_proxy_host':
      setting => 'http_proxy_host',
      value   => $http_proxy_host,
    }
  }
  if $http_proxy_port != $::puppet::params::master::http_proxy_port {
    ini_setting { 'master http_proxy_port':
      setting => 'http_proxy_port',
      value   => $http_proxy_port,
    }
  }
  if $filetimeout != $::puppet::params::master::filetimeout {
    ini_setting { 'master filetimeout':
      setting => 'filetimeout',
      value   => $filetimeout,
    }
  }
  if $queue_type != $::puppet::params::master::queue_type {
    ini_setting { 'master queue_type':
      setting => 'queue_type',
      value   => $queue_type,
    }
  }
  if $queue_source != $::puppet::params::master::queue_source {
    ini_setting { 'master queue_source':
      setting => 'queue_source',
      value   => $queue_source,
    }
  }
  if $async_storeconfigs != $::puppet::params::master::async_storeconfigs {
    ini_setting { 'master async_storeconfigs':
      setting => 'async_storeconfigs',
      value   => $async_storeconfigs,
    }
  }
  if $thin_storeconfigs != $::puppet::params::master::thin_storeconfigs {
    ini_setting { 'master thin_storeconfigs':
      setting => 'thin_storeconfigs',
      value   => $thin_storeconfigs,
    }
  }
  if $config_version != $::puppet::params::master::config_version {
    ini_setting { 'master config_version':
      setting => 'config_version',
      value   => $config_version,
    }
  }
  if $zlib != $::puppet::params::master::zlib {
    ini_setting { 'master zlib':
      setting => 'zlib',
      value   => $zlib,
    }
  }
  if $prerun_command != $::puppet::params::master::prerun_command {
    ini_setting { 'master prerun_command':
      setting => 'prerun_command',
      value   => $prerun_command,
    }
  }
  if $postrun_command != $::puppet::params::master::postrun_command {
    ini_setting { 'master postrun_command':
      setting => 'postrun_command',
      value   => $postrun_command,
    }
  }
  if $freeze_main != $::puppet::params::master::freeze_main {
    ini_setting { 'master freeze_main':
      setting => 'freeze_main',
      value   => $freeze_main,
    }
  }
  if $stringify_facts != $::puppet::params::master::stringify_facts {
    ini_setting { 'master stringify_facts':
      setting => 'stringify_facts',
      value   => $stringify_facts,
    }
  }
  if $trusted_node_data != $::puppet::params::master::trusted_node_data {
    ini_setting { 'master trusted_node_data':
      setting => 'trusted_node_data',
      value   => $trusted_node_data,
    }
  }
  if $certdnsnames != $::puppet::params::master::certdnsnames {
    ini_setting { 'master certdnsnames':
      setting => 'certdnsnames',
      value   => $certdnsnames,
    }
  }
  if $dns_alt_names != $::puppet::params::master::dns_alt_names {
    ini_setting { 'master dns_alt_names':
      setting => 'dns_alt_names',
      value   => $dns_alt_names,
    }
  }
  if $csr_attributes != $::puppet::params::master::csr_attributes {
    ini_setting { 'master csr_attributes':
      setting => 'csr_attributes',
      value   => $csr_attributes,
    }
  }
  if $certdir != $::puppet::params::master::certdir {
    ini_setting { 'master certdir':
      setting => 'certdir',
      value   => $certdir,
    }
  }
  if $ssldir != $::puppet::params::master::ssldir {
    ini_setting { 'master ssldir':
      setting => 'ssldir',
      value   => $ssldir,
    }
  }
  if $publickeydir != $::puppet::params::master::publickeydir {
    ini_setting { 'master publickeydir':
      setting => 'publickeydir',
      value   => $publickeydir,
    }
  }
  if $requestdir != $::puppet::params::master::requestdir {
    ini_setting { 'master requestdir':
      setting => 'requestdir',
      value   => $requestdir,
    }
  }
  if $privatekeydir != $::puppet::params::master::privatekeydir {
    ini_setting { 'master privatekeydir':
      setting => 'privatekeydir',
      value   => $privatekeydir,
    }
  }
  if $privatedir != $::puppet::params::master::privatedir {
    ini_setting { 'master privatedir':
      setting => 'privatedir',
      value   => $privatedir,
    }
  }
  if $passfile != $::puppet::params::master::passfile {
    ini_setting { 'master passfile':
      setting => 'passfile',
      value   => $passfile,
    }
  }
  if $hostcsr != $::puppet::params::master::hostcsr {
    ini_setting { 'master hostcsr':
      setting => 'hostcsr',
      value   => $hostcsr,
    }
  }
  if $hostcert != $::puppet::params::master::hostcert {
    ini_setting { 'master hostcert':
      setting => 'hostcert',
      value   => $hostcert,
    }
  }
  if $hostprivkey != $::puppet::params::master::hostprivkey {
    ini_setting { 'master hostprivkey':
      setting => 'hostprivkey',
      value   => $hostprivkey,
    }
  }
  if $hostpubkey != $::puppet::params::master::hostpubkey {
    ini_setting { 'master hostpubkey':
      setting => 'hostpubkey',
      value   => $hostpubkey,
    }
  }
  if $localcacert != $::puppet::params::master::localcacert {
    ini_setting { 'master localcacert':
      setting => 'localcacert',
      value   => $localcacert,
    }
  }
  if $ssl_client_ca_auth != $::puppet::params::master::ssl_client_ca_auth {
    ini_setting { 'master ssl_client_ca_auth':
      setting => 'ssl_client_ca_auth',
      value   => $ssl_client_ca_auth,
    }
  }
  if $ssl_server_ca_auth != $::puppet::params::master::ssl_server_ca_auth {
    ini_setting { 'master ssl_server_ca_auth':
      setting => 'ssl_server_ca_auth',
      value   => $ssl_server_ca_auth,
    }
  }
  if $hostcrl != $::puppet::params::master::hostcrl {
    ini_setting { 'master hostcrl':
      setting => 'hostcrl',
      value   => $hostcrl,
    }
  }
  if $certificate_revocation != $::puppet::params::master::certificate_revocation {
    ini_setting { 'master certificate_revocation':
      setting => 'certificate_revocation',
      value   => $certificate_revocation,
    }
  }
  if $certificate_expire_warning != $::puppet::params::master::certificate_expire_warning {
    ini_setting { 'master certificate_expire_warning':
      setting => 'certificate_expire_warning',
      value   => $certificate_expire_warning,
    }
  }
  if $plugindest != $::puppet::params::master::plugindest {
    ini_setting { 'master plugindest':
      setting => 'plugindest',
      value   => $plugindest,
    }
  }
  if $pluginsource != $::puppet::params::master::pluginsource {
    ini_setting { 'master pluginsource':
      setting => 'pluginsource',
      value   => $pluginsource,
    }
  }
  if $pluginfactdest != $::puppet::params::master::pluginfactdest {
    ini_setting { 'master pluginfactdest':
      setting => 'pluginfactdest',
      value   => $pluginfactdest,
    }
  }
  if $pluginfactsource != $::puppet::params::master::pluginfactsource {
    ini_setting { 'master pluginfactsource':
      setting => 'pluginfactsource',
      value   => $pluginfactsource,
    }
  }
  if $pluginsync != $::puppet::params::master::pluginsync {
    ini_setting { 'master pluginsync':
      setting => 'pluginsync',
      value   => $pluginsync,
    }
  }
  if $pluginsignore != $::puppet::params::master::pluginsignore {
    ini_setting { 'master pluginsignore':
      setting => 'pluginsignore',
      value   => $pluginsignore,
    }
  }
  if $factpath != $::puppet::params::master::factpath {
    ini_setting { 'master factpath':
      setting => 'factpath',
      value   => $factpath,
    }
  }
  if $external_nodes != $::puppet::params::master::external_nodes {
    ini_setting { 'master external_nodes':
      setting => 'external_nodes',
      value   => $external_nodes,
    }
  }
  if $module_repository != $::puppet::params::master::module_repository {
    ini_setting { 'master module_repository':
      setting => 'module_repository',
      value   => $module_repository,
    }
  }
  if $module_working_dir != $::puppet::params::master::module_working_dir {
    ini_setting { 'master module_working_dir':
      setting => 'module_working_dir',
      value   => $module_working_dir,
    }
  }
  if $module_skeleton_dir != $::puppet::params::master::module_skeleton_dir {
    ini_setting { 'master module_skeleton_dir':
      setting => 'module_skeleton_dir',
      value   => $module_skeleton_dir,
    }
  }
  if $cadir != $::puppet::params::master::cadir {
    ini_setting { 'master cadir':
      setting => 'cadir',
      value   => $cadir,
    }
  }
  if $cacert != $::puppet::params::master::cacert {
    ini_setting { 'master cacert':
      setting => 'cacert',
      value   => $cacert,
    }
  }
  if $cakey != $::puppet::params::master::cakey {
    ini_setting { 'master cakey':
      setting => 'cakey',
      value   => $cakey,
    }
  }
  if $capub != $::puppet::params::master::capub {
    ini_setting { 'master capub':
      setting => 'capub',
      value   => $capub,
    }
  }
  if $cacrl != $::puppet::params::master::cacrl {
    ini_setting { 'master cacrl':
      setting => 'cacrl',
      value   => $cacrl,
    }
  }
  if $caprivatedir != $::puppet::params::master::caprivatedir {
    ini_setting { 'master caprivatedir':
      setting => 'caprivatedir',
      value   => $caprivatedir,
    }
  }
  if $csrdir != $::puppet::params::master::csrdir {
    ini_setting { 'master csrdir':
      setting => 'csrdir',
      value   => $csrdir,
    }
  }
  if $signeddir != $::puppet::params::master::signeddir {
    ini_setting { 'master signeddir':
      setting => 'signeddir',
      value   => $signeddir,
    }
  }
  if $capass != $::puppet::params::master::capass {
    ini_setting { 'master capass':
      setting => 'capass',
      value   => $capass,
    }
  }
  if $serial != $::puppet::params::master::serial {
    ini_setting { 'master serial':
      setting => 'serial',
      value   => $serial,
    }
  }
  if $autosign != $::puppet::params::master::autosign {
    ini_setting { 'master autosign':
      setting => 'autosign',
      value   => $autosign,
    }
  }
  if $allow_duplicate_certs != $::puppet::params::master::allow_duplicate_certs {
    ini_setting { 'master allow_duplicate_certs':
      setting => 'allow_duplicate_certs',
      value   => $allow_duplicate_certs,
    }
  }
  if $ca_ttl != $::puppet::params::master::ca_ttl {
    ini_setting { 'master ca_ttl':
      setting => 'ca_ttl',
      value   => $ca_ttl,
    }
  }
  if $req_bits != $::puppet::params::master::req_bits {
    ini_setting { 'master req_bits':
      setting => 'req_bits',
      value   => $req_bits,
    }
  }
  if $keylength != $::puppet::params::master::keylength {
    ini_setting { 'master keylength':
      setting => 'keylength',
      value   => $keylength,
    }
  }
  if $cert_inventory != $::puppet::params::master::cert_inventory {
    ini_setting { 'master cert_inventory':
      setting => 'cert_inventory',
      value   => $cert_inventory,
    }
  }
  if $config_file_name != $::puppet::params::master::config_file_name {
    ini_setting { 'master config_file_name':
      setting => 'config_file_name',
      value   => $config_file_name,
    }
  }
  if $config != $::puppet::params::master::config {
    ini_setting { 'master config':
      setting => 'config',
      value   => $config,
    }
  }
  if $pidfile != $::puppet::params::master::pidfile {
    ini_setting { 'master pidfile':
      setting => 'pidfile',
      value   => $pidfile,
    }
  }
  if $bindaddress != $::puppet::params::master::bindaddress {
    ini_setting { 'master bindaddress':
      setting => 'bindaddress',
      value   => $bindaddress,
    }
  }
  if $manifestdir != $::puppet::params::master::manifestdir {
    ini_setting { 'master manifestdir':
      setting => 'manifestdir',
      value   => $manifestdir,
    }
  }
  if $manifest != $::puppet::params::master::manifest {
    ini_setting { 'master manifest':
      setting => 'manifest',
      value   => $manifest,
    }
  }
  if $code != $::puppet::params::master::code {
    ini_setting { 'master code':
      setting => 'code',
      value   => $code,
    }
  }
  if $masterlog != $::puppet::params::master::masterlog {
    ini_setting { 'master masterlog':
      setting => 'masterlog',
      value   => $masterlog,
    }
  }
  if $masterhttplog != $::puppet::params::master::masterhttplog {
    ini_setting { 'master masterhttplog':
      setting => 'masterhttplog',
      value   => $masterhttplog,
    }
  }
  if $masterport != $::puppet::params::master::masterport {
    ini_setting { 'master masterport':
      setting => 'masterport',
      value   => $masterport,
    }
  }
  if $node_name != $::puppet::params::master::node_name {
    ini_setting { 'master node_name':
      setting => 'node_name',
      value   => $node_name,
    }
  }
  if $bucketdir != $::puppet::params::master::bucketdir {
    ini_setting { 'master bucketdir':
      setting => 'bucketdir',
      value   => $bucketdir,
    }
  }
  if $rest_authconfig != $::puppet::params::master::rest_authconfig {
    ini_setting { 'master rest_authconfig':
      setting => 'rest_authconfig',
      value   => $rest_authconfig,
    }
  }
  if $ca != $::puppet::params::master::ca {
    ini_setting { 'master ca':
      setting => 'ca',
      value   => $ca,
    }
  }
  if $yamldir != $::puppet::params::master::yamldir {
    ini_setting { 'master yamldir':
      setting => 'yamldir',
      value   => $yamldir,
    }
  }
  if $server_datadir != $::puppet::params::master::server_datadir {
    ini_setting { 'master server_datadir':
      setting => 'server_datadir',
      value   => $server_datadir,
    }
  }
  if $reportdir != $::puppet::params::master::reportdir {
    ini_setting { 'master reportdir':
      setting => 'reportdir',
      value   => $reportdir,
    }
  }
  if $reporturl != $::puppet::params::master::reporturl {
    ini_setting { 'master reporturl':
      setting => 'reporturl',
      value   => $reporturl,
    }
  }
  if $fileserverconfig != $::puppet::params::master::fileserverconfig {
    ini_setting { 'master fileserverconfig':
      setting => 'fileserverconfig',
      value   => $fileserverconfig,
    }
  }
  if $strict_hostname_checking != $::puppet::params::master::strict_hostname_checking {
    ini_setting { 'master strict_hostname_checking':
      setting => 'strict_hostname_checking',
      value   => $strict_hostname_checking,
    }
  }
  if $rrddir != $::puppet::params::master::rrddir {
    ini_setting { 'master rrddir':
      setting => 'rrddir',
      value   => $rrddir,
    }
  }
  if $rrdinterval != $::puppet::params::master::rrdinterval {
    ini_setting { 'master rrdinterval':
      setting => 'rrdinterval',
      value   => $rrdinterval,
    }
  }
  if $devicedir != $::puppet::params::master::devicedir {
    ini_setting { 'master devicedir':
      setting => 'devicedir',
      value   => $devicedir,
    }
  }
  if $deviceconfig != $::puppet::params::master::deviceconfig {
    ini_setting { 'master deviceconfig':
      setting => 'deviceconfig',
      value   => $deviceconfig,
    }
  }
  if $node_name_value != $::puppet::params::master::node_name_value {
    ini_setting { 'master node_name_value':
      setting => 'node_name_value',
      value   => $node_name_value,
    }
  }
  if $node_name_fact != $::puppet::params::master::node_name_fact {
    ini_setting { 'master node_name_fact':
      setting => 'node_name_fact',
      value   => $node_name_fact,
    }
  }
  if $localconfig != $::puppet::params::master::localconfig {
    ini_setting { 'master localconfig':
      setting => 'localconfig',
      value   => $localconfig,
    }
  }
  if $statefile != $::puppet::params::master::statefile {
    ini_setting { 'master statefile':
      setting => 'statefile',
      value   => $statefile,
    }
  }
  if $clientyamldir != $::puppet::params::master::clientyamldir {
    ini_setting { 'master clientyamldir':
      setting => 'clientyamldir',
      value   => $clientyamldir,
    }
  }
  if $client_datadir != $::puppet::params::master::client_datadir {
    ini_setting { 'master client_datadir':
      setting => 'client_datadir',
      value   => $client_datadir,
    }
  }
  if $classfile != $::puppet::params::master::classfile {
    ini_setting { 'master classfile':
      setting => 'classfile',
      value   => $classfile,
    }
  }
  if $resourcefile != $::puppet::params::master::resourcefile {
    ini_setting { 'master resourcefile':
      setting => 'resourcefile',
      value   => $resourcefile,
    }
  }
  if $puppetdlog != $::puppet::params::master::puppetdlog {
    ini_setting { 'master puppetdlog':
      setting => 'puppetdlog',
      value   => $puppetdlog,
    }
  }
  if $use_srv_records != $::puppet::params::master::use_srv_records {
    ini_setting { 'master use_srv_records':
      setting => 'use_srv_records',
      value   => $use_srv_records,
    }
  }
  if $srv_domain != $::puppet::params::master::srv_domain {
    ini_setting { 'master srv_domain':
      setting => 'srv_domain',
      value   => $srv_domain,
    }
  }
  if $ignoreschedules != $::puppet::params::master::ignoreschedules {
    ini_setting { 'master ignoreschedules':
      setting => 'ignoreschedules',
      value   => $ignoreschedules,
    }
  }
  if $default_schedules != $::puppet::params::master::default_schedules {
    ini_setting { 'master default_schedules':
      setting => 'default_schedules',
      value   => $default_schedules,
    }
  }
  if $puppetport != $::puppet::params::master::puppetport {
    ini_setting { 'master puppetport':
      setting => 'puppetport',
      value   => $puppetport,
    }
  }
  if $noop != $::puppet::params::master::noop {
    ini_setting { 'master noop':
      setting => 'noop',
      value   => $noop,
    }
  }
  if $runinterval != $::puppet::params::master::runinterval {
    ini_setting { 'master runinterval':
      setting => 'runinterval',
      value   => $runinterval,
    }
  }
  if $listen != $::puppet::params::master::listen {
    ini_setting { 'master listen':
      setting => 'listen',
      value   => $listen,
    }
  }
  if $ca_server != $::puppet::params::master::ca_server {
    ini_setting { 'master ca_server':
      setting => 'ca_server',
      value   => $ca_server,
    }
  }
  if $ca_port != $::puppet::params::master::ca_port {
    ini_setting { 'master ca_port':
      setting => 'ca_port',
      value   => $ca_port,
    }
  }
  if $catalog_format != $::puppet::params::master::catalog_format {
    ini_setting { 'master catalog_format':
      setting => 'catalog_format',
      value   => $catalog_format,
    }
  }
  if $preferred_serialization_format != $::puppet::params::master::preferred_serialization_format {
    ini_setting { 'master preferred_serialization_format':
      setting => 'preferred_serialization_format',
      value   => $preferred_serialization_format,
    }
  }
  if $report_serialization_format != $::puppet::params::master::report_serialization_format {
    ini_setting { 'master report_serialization_format':
      setting => 'report_serialization_format',
      value   => $report_serialization_format,
    }
  }
  if $legacy_query_parameter_serialization != $::puppet::params::master::legacy_query_parameter_serialization {
    ini_setting { 'master legacy_query_parameter_serialization':
      setting => 'legacy_query_parameter_serialization',
      value   => $legacy_query_parameter_serialization,
    }
  }
  if $agent_catalog_run_lockfile != $::puppet::params::master::agent_catalog_run_lockfile {
    ini_setting { 'master agent_catalog_run_lockfile':
      setting => 'agent_catalog_run_lockfile',
      value   => $agent_catalog_run_lockfile,
    }
  }
  if $agent_disabled_lockfile != $::puppet::params::master::agent_disabled_lockfile {
    ini_setting { 'master agent_disabled_lockfile':
      setting => 'agent_disabled_lockfile',
      value   => $agent_disabled_lockfile,
    }
  }
  if $usecacheonfailure != $::puppet::params::master::usecacheonfailure {
    ini_setting { 'master usecacheonfailure':
      setting => 'usecacheonfailure',
      value   => $usecacheonfailure,
    }
  }
  if $use_cached_catalog != $::puppet::params::master::use_cached_catalog {
    ini_setting { 'master use_cached_catalog':
      setting => 'use_cached_catalog',
      value   => $use_cached_catalog,
    }
  }
  if $ignoremissingtypes != $::puppet::params::master::ignoremissingtypes {
    ini_setting { 'master ignoremissingtypes':
      setting => 'ignoremissingtypes',
      value   => $ignoremissingtypes,
    }
  }
  if $ignorecache != $::puppet::params::master::ignorecache {
    ini_setting { 'master ignorecache':
      setting => 'ignorecache',
      value   => $ignorecache,
    }
  }
  if $dynamicfacts != $::puppet::params::master::dynamicfacts {
    ini_setting { 'master dynamicfacts':
      setting => 'dynamicfacts',
      value   => $dynamicfacts,
    }
  }
  if $splaylimit != $::puppet::params::master::splaylimit {
    ini_setting { 'master splaylimit':
      setting => 'splaylimit',
      value   => $splaylimit,
    }
  }
  if $splay != $::puppet::params::master::splay {
    ini_setting { 'master splay':
      setting => 'splay',
      value   => $splay,
    }
  }
  if $clientbucketdir != $::puppet::params::master::clientbucketdir {
    ini_setting { 'master clientbucketdir':
      setting => 'clientbucketdir',
      value   => $clientbucketdir,
    }
  }
  if $configtimeout != $::puppet::params::master::configtimeout {
    ini_setting { 'master configtimeout':
      setting => 'configtimeout',
      value   => $configtimeout,
    }
  }
  if $report_server != $::puppet::params::master::report_server {
    ini_setting { 'master report_server':
      setting => 'report_server',
      value   => $report_server,
    }
  }
  if $report_port != $::puppet::params::master::report_port {
    ini_setting { 'master report_port':
      setting => 'report_port',
      value   => $report_port,
    }
  }
  if $inventory_server != $::puppet::params::master::inventory_server {
    ini_setting { 'master inventory_server':
      setting => 'inventory_server',
      value   => $inventory_server,
    }
  }
  if $inventory_port != $::puppet::params::master::inventory_port {
    ini_setting { 'master inventory_port':
      setting => 'inventory_port',
      value   => $inventory_port,
    }
  }
  if $report != $::puppet::params::master::report {
    ini_setting { 'master report':
      setting => 'report',
      value   => $report,
    }
  }
  if $lastrunfile != $::puppet::params::master::lastrunfile {
    ini_setting { 'master lastrunfile':
      setting => 'lastrunfile',
      value   => $lastrunfile,
    }
  }
  if $lastrunreport != $::puppet::params::master::lastrunreport {
    ini_setting { 'master lastrunreport':
      setting => 'lastrunreport',
      value   => $lastrunreport,
    }
  }
  if $graph != $::puppet::params::master::graph {
    ini_setting { 'master graph':
      setting => 'graph',
      value   => $graph,
    }
  }
  if $graphdir != $::puppet::params::master::graphdir {
    ini_setting { 'master graphdir':
      setting => 'graphdir',
      value   => $graphdir,
    }
  }
  if $http_compression != $::puppet::params::master::http_compression {
    ini_setting { 'master http_compression':
      setting => 'http_compression',
      value   => $http_compression,
    }
  }
  if $waitforcert != $::puppet::params::master::waitforcert {
    ini_setting { 'master waitforcert':
      setting => 'waitforcert',
      value   => $waitforcert,
    }
  }
  if $ordering != $::puppet::params::master::ordering {
    ini_setting { 'master ordering':
      setting => 'ordering',
      value   => $ordering,
    }
  }
  if $tagmap != $::puppet::params::master::tagmap {
    ini_setting { 'master tagmap':
      setting => 'tagmap',
      value   => $tagmap,
    }
  }
  if $sendmail != $::puppet::params::master::sendmail {
    ini_setting { 'master sendmail':
      setting => 'sendmail',
      value   => $sendmail,
    }
  }
  if $reportfrom != $::puppet::params::master::reportfrom {
    ini_setting { 'master reportfrom':
      setting => 'reportfrom',
      value   => $reportfrom,
    }
  }
  if $smtpserver != $::puppet::params::master::smtpserver {
    ini_setting { 'master smtpserver':
      setting => 'smtpserver',
      value   => $smtpserver,
    }
  }
  if $smtpport != $::puppet::params::master::smtpport {
    ini_setting { 'master smtpport':
      setting => 'smtpport',
      value   => $smtpport,
    }
  }
  if $smtphelo != $::puppet::params::master::smtphelo {
    ini_setting { 'master smtphelo':
      setting => 'smtphelo',
      value   => $smtphelo,
    }
  }
  if $dblocation != $::puppet::params::master::dblocation {
    ini_setting { 'master dblocation':
      setting => 'dblocation',
      value   => $dblocation,
    }
  }
  if $dbadapter != $::puppet::params::master::dbadapter {
    ini_setting { 'master dbadapter':
      setting => 'dbadapter',
      value   => $dbadapter,
    }
  }
  if $dbmigrate != $::puppet::params::master::dbmigrate {
    ini_setting { 'master dbmigrate':
      setting => 'dbmigrate',
      value   => $dbmigrate,
    }
  }
  if $dbname != $::puppet::params::master::dbname {
    ini_setting { 'master dbname':
      setting => 'dbname',
      value   => $dbname,
    }
  }
  if $dbserver != $::puppet::params::master::dbserver {
    ini_setting { 'master dbserver':
      setting => 'dbserver',
      value   => $dbserver,
    }
  }
  if $dbport != $::puppet::params::master::dbport {
    ini_setting { 'master dbport':
      setting => 'dbport',
      value   => $dbport,
    }
  }
  if $dbuser != $::puppet::params::master::dbuser {
    ini_setting { 'master dbuser':
      setting => 'dbuser',
      value   => $dbuser,
    }
  }
  if $dbpassword != $::puppet::params::master::dbpassword {
    ini_setting { 'master dbpassword':
      setting => 'dbpassword',
      value   => $dbpassword,
    }
  }
  if $dbconnections != $::puppet::params::master::dbconnections {
    ini_setting { 'master dbconnections':
      setting => 'dbconnections',
      value   => $dbconnections,
    }
  }
  if $dbsocket != $::puppet::params::master::dbsocket {
    ini_setting { 'master dbsocket':
      setting => 'dbsocket',
      value   => $dbsocket,
    }
  }
  if $railslog != $::puppet::params::master::railslog {
    ini_setting { 'master railslog':
      setting => 'railslog',
      value   => $railslog,
    }
  }
  if $rails_loglevel != $::puppet::params::master::rails_loglevel {
    ini_setting { 'master rails_loglevel':
      setting => 'rails_loglevel',
      value   => $rails_loglevel,
    }
  }
  if $couchdb_url != $::puppet::params::master::couchdb_url {
    ini_setting { 'master couchdb_url':
      setting => 'couchdb_url',
      value   => $couchdb_url,
    }
  }
  if $tags != $::puppet::params::master::tags {
    ini_setting { 'master tags':
      setting => 'tags',
      value   => $tags,
    }
  }
  if $evaltrace != $::puppet::params::master::evaltrace {
    ini_setting { 'master evaltrace':
      setting => 'evaltrace',
      value   => $evaltrace,
    }
  }
  if $summarize != $::puppet::params::master::summarize {
    ini_setting { 'master summarize':
      setting => 'summarize',
      value   => $summarize,
    }
  }
  if $ldapssl != $::puppet::params::master::ldapssl {
    ini_setting { 'master ldapssl':
      setting => 'ldapssl',
      value   => $ldapssl,
    }
  }
  if $ldaptls != $::puppet::params::master::ldaptls {
    ini_setting { 'master ldaptls':
      setting => 'ldaptls',
      value   => $ldaptls,
    }
  }
  if $ldapserver != $::puppet::params::master::ldapserver {
    ini_setting { 'master ldapserver':
      setting => 'ldapserver',
      value   => $ldapserver,
    }
  }
  if $ldapport != $::puppet::params::master::ldapport {
    ini_setting { 'master ldapport':
      setting => 'ldapport',
      value   => $ldapport,
    }
  }
  if $ldapstring != $::puppet::params::master::ldapstring {
    ini_setting { 'master ldapstring':
      setting => 'ldapstring',
      value   => $ldapstring,
    }
  }
  if $ldapclassattrs != $::puppet::params::master::ldapclassattrs {
    ini_setting { 'master ldapclassattrs':
      setting => 'ldapclassattrs',
      value   => $ldapclassattrs,
    }
  }
  if $ldapstackedattrs != $::puppet::params::master::ldapstackedattrs {
    ini_setting { 'master ldapstackedattrs':
      setting => 'ldapstackedattrs',
      value   => $ldapstackedattrs,
    }
  }
  if $ldapattrs != $::puppet::params::master::ldapattrs {
    ini_setting { 'master ldapattrs':
      setting => 'ldapattrs',
      value   => $ldapattrs,
    }
  }
  if $ldapparentattr != $::puppet::params::master::ldapparentattr {
    ini_setting { 'master ldapparentattr':
      setting => 'ldapparentattr',
      value   => $ldapparentattr,
    }
  }
  if $ldapuser != $::puppet::params::master::ldapuser {
    ini_setting { 'master ldapuser':
      setting => 'ldapuser',
      value   => $ldapuser,
    }
  }
  if $ldappassword != $::puppet::params::master::ldappassword {
    ini_setting { 'master ldappassword':
      setting => 'ldappassword',
      value   => $ldappassword,
    }
  }
  if $ldapbase != $::puppet::params::master::ldapbase {
    ini_setting { 'master ldapbase':
      setting => 'ldapbase',
      value   => $ldapbase,
    }
  }
  if $templatedir != $::puppet::params::master::templatedir {
    ini_setting { 'master templatedir':
      setting => 'templatedir',
      value   => $templatedir,
    }
  }
  if $allow_variables_with_dashes != $::puppet::params::master::allow_variables_with_dashes {
    ini_setting { 'master allow_variables_with_dashes':
      setting => 'allow_variables_with_dashes',
      value   => $allow_variables_with_dashes,
    }
  }
  if $parser != $::puppet::params::master::parser {
    ini_setting { 'master parser':
      setting => 'parser',
      value   => $parser,
    }
  }
  if $max_errors != $::puppet::params::master::max_errors {
    ini_setting { 'master max_errors':
      setting => 'max_errors',
      value   => $max_errors,
    }
  }
  if $max_warnings != $::puppet::params::master::max_warnings {
    ini_setting { 'master max_warnings':
      setting => 'max_warnings',
      value   => $max_warnings,
    }
  }
  if $max_deprecations != $::puppet::params::master::max_deprecations {
    ini_setting { 'master max_deprecations':
      setting => 'max_deprecations',
      value   => $max_deprecations,
    }
  }
  if $document_all != $::puppet::params::master::document_all {
    ini_setting { 'master document_all':
      setting => 'document_all',
      value   => $document_all,
    }
  }
}
