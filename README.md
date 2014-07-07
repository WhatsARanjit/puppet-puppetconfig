# PuppetConfig Module

## Overview

This will create and manage configurations in puppet.conf.

## Capabilities

Installalation includes:

- Main stanza
- Master stanza
- Agent stanza
- Create any new stanza with values

Requires:

- Puppetlabs/inifile module to use the ini_setting type.

## PuppetConfig parameters
See Puppet documentation for variable definitions.<br />
http://docs.puppetlabs.com/references/latest/configuration.html

* `config`<br />
Default: /etc/puppetlabs/puppet/puppet.conf

## Example Usage

Install puppet:

```puppet
include ::puppetconfig::main
include ::puppetconfig::master
include ::puppetconfig::agent
```

Install puppetconfig::main with custom parameters:

```puppet
class { '::puppetconfig::main':
  modulepath   => '/opt/modules',
  archive_file => false,
}
```

Create a new stanza with values

```puppet
define ::puppetconfig::config { 'test manifests':
  section => 'test',
  setting => 'manifests',
  value   => '/home/foo/manifests/site.pp',
}
define ::puppetconfig::config { 'test modulepath':
  section => 'test',
  setting => 'modulepath',
  value   => '/home/foo/modules',
}
```
