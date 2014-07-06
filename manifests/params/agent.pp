class puppet::params::agent {
  $confdir                              = '/etc/puppetlabs/puppet'
  $vardir                               = '/var/opt/lib/pe-puppet'
  $section                              = 'agent'
  $logdir                               = '/var/log/pe-puppet'
  $priority                             = ''
  $trace                                = false
  $profile                              = false
  $autoflush                            = true
  $syslogfacility                       = 'daemon'
  $statedir                             = '/var/opt/lib/pe-puppet/state'
  $rundir                               = '/var/run/pe-puppet'
  $genmanifest                          = false
  $configprint                          = ''
  $color                                = 'ansi'
  $mkusers                              = false
  $manage_internal_file_permissions     = true
  $onetime                              = false
  $path                                 = 'none'
  $libdir                               = '/var/opt/lib/pe-puppet/lib'
  $ignoreimport                         = false
  $environment                          = 'production'
  $diff_args                            = '-u'
  $diff                                 = 'diff'
  $show_diff                            = false
  $daemonize                            = true
  $maximum_uid                          = '4294967290'
  $route_file                           = '/etc/puppetlabs/puppet/routes.yaml'
  $node_terminus                        = 'rest'
  $node_cache_terminus                  = ''
  $data_binding_terminus                = 'hiera'
  $hiera_config                         = '/etc/puppetlabs/puppet/hiera.yaml'
  $binder                               = false
  $binder_config                        = ''
  $catalog_terminus                     = 'rest'
  $catalog_cache_terminus               = 'json'
  $facts_terminus                       = 'facter'
  $inventory_terminus                   = 'facter'
  $default_file_terminus                = 'rest'
  $httplog                              = '/var/log/pe-puppet/http.log'
  $http_proxy_host                      = 'none'
  $http_proxy_port                      = '3128'
  $filetimeout                          = '15'
  $queue_type                           = 'stomp'
  $queue_source                         = 'stomp://localhost:61613/'
  $async_storeconfigs                   = false
  $thin_storeconfigs                    = false
  $config_version                       = ''
  $zlib                                 = true
  $prerun_command                       = ''
  $postrun_command                      = ''
  $freeze_main                          = false
  $stringify_facts                      = true
  $trusted_node_data                    = false
  $certname                             = 'master.puppetlabs.vm'
  $certdnsnames                         = ''
  $dns_alt_names                        = 'master,master.puppetlabs.vm,puppet,puppet.puppetlabs.vm'
  $csr_attributes                       = '/etc/puppetlabs/puppet/csr_attributes.yaml'
  $certdir                              = '/etc/puppetlabs/puppet/ssl/certs'
  $ssldir                               = '/etc/puppetlabs/puppet/ssl'
  $publickeydir                         = '/etc/puppetlabs/puppet/ssl/public_keys'
  $requestdir                           = '/etc/puppetlabs/puppet/ssl/certificate_requests'
  $privatekeydir                        = '/etc/puppetlabs/puppet/ssl/private_keys'
  $privatedir                           = '/etc/puppetlabs/puppet/ssl/private'
  $passfile                             = '/etc/puppetlabs/puppet/ssl/private/password'
  $hostcsr                              = '/etc/puppetlabs/puppet/ssl/csr_master.puppetlabs.vm.pem'
  $hostcert                             = '/etc/puppetlabs/puppet/ssl/certs/master.puppetlabs.vm.pem'
  $hostprivkey                          = '/etc/puppetlabs/puppet/ssl/private_keys/master.puppetlabs.vm.pem'
  $hostpubkey                           = '/etc/puppetlabs/puppet/ssl/public_keys/master.puppetlabs.vm.pem'
  $localcacert                          = '/etc/puppetlabs/puppet/ssl/certs/ca.pem'
  $ssl_client_ca_auth                   = ''
  $ssl_server_ca_auth                   = ''
  $hostcrl                              = '/etc/puppetlabs/puppet/ssl/crl.pem'
  $certificate_revocation               = true
  $certificate_expire_warning           = '5184000'
  $plugindest                           = '/var/opt/lib/pe-puppet/lib'
  $pluginsource                         = 'puppet://master.puppetlabs.vm/plugins'
  $pluginfactdest                       = '/var/opt/lib/pe-puppet/facts.d'
  $pluginfactsource                     = 'puppet://master.puppetlabs.vm/pluginfacts'
  $pluginsync                           = true
  $pluginsignore                        = '.svn CVS .git'
  $factpath                             = '/var/opt/lib/pe-puppet/lib/facter:/var/opt/lib/pe-puppet/facts'
  $external_nodes                       = 'none'
  $module_repository                    = 'https://forgeapi.puppetlabs.com'
  $module_working_dir                   = '/var/opt/lib/pe-puppet/puppet-module'
  $module_skeleton_dir                  = '/var/opt/lib/pe-puppet/puppet-module/skeleton'
  $ca_name                              = 'Puppet CA: master.puppetlabs.vm'
  $cadir                                = '/etc/puppetlabs/puppet/ssl/ca'
  $cacert                               = '/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem'
  $cakey                                = '/etc/puppetlabs/puppet/ssl/ca/ca_key.pem'
  $capub                                = '/etc/puppetlabs/puppet/ssl/ca/ca_pub.pem'
  $cacrl                                = '/etc/puppetlabs/puppet/ssl/ca/ca_crl.pem'
  $caprivatedir                         = '/etc/puppetlabs/puppet/ssl/ca/private'
  $csrdir                               = '/etc/puppetlabs/puppet/ssl/ca/requests'
  $signeddir                            = '/etc/puppetlabs/puppet/ssl/ca/signed'
  $capass                               = '/etc/puppetlabs/puppet/ssl/ca/private/ca.pass'
  $serial                               = '/etc/puppetlabs/puppet/ssl/ca/serial'
  $autosign                             = '/etc/puppetlabs/puppet/autosign.conf'
  $allow_duplicate_certs                = false
  $ca_ttl                               = '157680000'
  $req_bits                             = '4096'
  $keylength                            = '4096'
  $cert_inventory                       = '/etc/puppetlabs/puppet/ssl/ca/inventory.txt'
  $config_file_name                     = 'puppet.conf'
  $config                               = '/etc/puppetlabs/puppet/puppet.conf'
  $pidfile                              = '/var/run/pe-puppet/agent.pid'
  $bindaddress                          = '0.0.0.0'
  $user                                 = 'pe-puppet'
  $group                                = 'pe-puppet'
  $manifestdir                          = '/etc/puppetlabs/puppet/manifests'
  $manifest                             = '/etc/puppetlabs/puppet/manifests/site.pp'
  $code                                 = ''
  $masterlog                            = '/var/log/pe-puppet/puppetmaster.log'
  $masterhttplog                        = '/var/log/pe-puppet/masterhttp.log'
  $masterport                           = '8140'
  $node_name                            = 'cert'
  $bucketdir                            = '/var/opt/lib/pe-puppet/bucket'
  $rest_authconfig                      = '/etc/puppetlabs/puppet/auth.conf'
  $ca                                   = true
  $modulepath                           = '/etc/puppetlabs/puppet/modules:/opt/puppet/share/puppet/modules'
  $ssl_client_header                    = 'HTTP_X_CLIENT_DN'
  $ssl_client_verify_header             = 'HTTP_X_CLIENT_VERIFY'
  $yamldir                              = '/var/opt/lib/pe-puppet/yaml'
  $server_datadir                       = '/var/opt/lib/pe-puppet/server_data'
  $reports                              = 'store'
  $reportdir                            = '/var/opt/lib/pe-puppet/reports'
  $reporturl                            = 'http://localhost:3000/reports/upload'
  $fileserverconfig                     = '/etc/puppetlabs/puppet/fileserver.conf'
  $strict_hostname_checking             = false
  $storeconfigs                         = false
  $storeconfigs_backend                 = 'active_record'
  $rrddir                               = '/var/opt/lib/pe-puppet/rrd'
  $rrdinterval                          = '1800'
  $devicedir                            = '/var/opt/lib/pe-puppet/devices'
  $deviceconfig                         = '/etc/puppetlabs/puppet/device.conf'
  $node_name_value                      = 'master.puppetlabs.vm'
  $node_name_fact                       = ''
  $localconfig                          = '/var/opt/lib/pe-puppet/localconfig'
  $statefile                            = '/var/opt/lib/pe-puppet/state/state.yaml'
  $clientyamldir                        = '/var/opt/lib/pe-puppet/client_yaml'
  $client_datadir                       = '/var/opt/lib/pe-puppet/client_data'
  $classfile                            = '/var/opt/lib/pe-puppet/classes.txt'
  $resourcefile                         = '/var/opt/lib/pe-puppet/state/resources.txt'
  $puppetdlog                           = '/var/log/pe-puppet/puppetd.log'
  $server                               = 'master.puppetlabs.vm'
  $use_srv_records                      = false
  $srv_domain                           = 'puppetlabs.vm'
  $ignoreschedules                      = false
  $default_schedules                    = true
  $puppetport                           = '8139'
  $runinterval                          = '1800'
  $listen                               = false
  $ca_server                            = 'master.puppetlabs.vm'
  $ca_port                              = '8140'
  $catalog_format                       = ''
  $preferred_serialization_format       = 'pson'
  $report_serialization_format          = 'pson'
  $legacy_query_parameter_serialization = false
  $agent_catalog_run_lockfile           = '/var/opt/lib/pe-puppet/state/agent_catalog_run.lock'
  $agent_disabled_lockfile              = '/var/opt/lib/pe-puppet/state/agent_disabled.lock'
  $usecacheonfailure                    = true
  $use_cached_catalog                   = false
  $ignoremissingtypes                   = false
  $ignorecache                          = false
  $dynamicfacts                         = 'memorysize,memoryfree,swapsize,swapfree'
  $splaylimit                           = '1800'
  $splay                                = false
  $clientbucketdir                      = '/var/opt/lib/pe-puppet/clientbucket'
  $configtimeout                        = '120'
  $report_server                        = 'master.puppetlabs.vm'
  $report_port                          = '8140'
  $inventory_server                     = 'master.puppetlabs.vm'
  $inventory_port                       = '8140'
  $report                               = true
  $lastrunfile                          = '/var/opt/lib/pe-puppet/state/last_run_summary.yaml'
  $lastrunreport                        = '/var/opt/lib/pe-puppet/state/last_run_report.yaml'
  $graph                                = true
  $graphdir                             = '/var/opt/lib/pe-puppet/state/graphs'
  $http_compression                     = false
  $waitforcert                          = '120'
  $ordering                             = 'title-hash'
  $archive_files                        = true
  $archive_file_server                  = 'master.puppetlabs.vm'
  $tagmap                               = '/etc/puppetlabs/puppet/tagmail.conf'
  $sendmail                             = '/usr/sbin/sendmail'
  $reportfrom                           = 'report@master.puppetlabs.vm'
  $smtpserver                           = 'none'
  $smtpport                             = '25'
  $smtphelo                             = 'master.puppetlabs.vm'
  $dblocation                           = '/var/opt/lib/pe-puppet/state/clientconfigs.sqlite3'
  $dbadapter                            = 'sqlite3'
  $dbmigrate                            = false
  $dbname                               = 'puppet'
  $dbserver                             = 'localhost'
  $dbport                               = ''
  $dbuser                               = 'puppet'
  $dbpassword                           = 'puppet'
  $dbconnections                        = ''
  $dbsocket                             = ''
  $railslog                             = '/var/log/pe-puppet/rails.log'
  $rails_loglevel                       = 'info'
  $couchdb_url                          = 'http://127.0.0.1:5984/puppet'
  $tags                                 = ''
  $evaltrace                            = false
  $summarize                            = false
  $ldapssl                              = false
  $ldaptls                              = false
  $ldapserver                           = 'ldap'
  $ldapport                             = '389'
  $ldapstring                           = '(&(objectclass                                                    = puppetClient)(cn = %s))'
  $ldapclassattrs                       = 'puppetclass'
  $ldapstackedattrs                     = 'puppetvar'
  $ldapattrs                            = 'all'
  $ldapparentattr                       = 'parentnode'
  $ldapuser                             = ''
  $ldappassword                         = ''
  $ldapbase                             = ''
  $templatedir                          = '/var/opt/lib/pe-puppet/templates'
  $allow_variables_with_dashes          = false
  $parser                               = 'current'
  $max_errors                           = '10'
  $max_warnings                         = '10'
  $max_deprecations                     = '10'
  $document_all                         = false
}
