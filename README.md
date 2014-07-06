# PuppetConfig Module

## Overview

This will create and manage configurations in puppet.conf.

## Capabilities

Installalation includes:

- Main stanza
- Master stanza
- Agent stanza

Requires:

- Puppetlabs/inifile module to use the ini_setting type.

## PuppetConfig parameters
See Puppet documentation for variable definitions.<br />
http://docs.puppetlabs.com/references/latest/configuration.html

* `config`<br />
Default: /etc/puppetlabs/puppet/puppet.conf

## Example Usage

Install transmission:

```puppet
include ::puppet::main
include ::puppet::master
include ::puppet::agent
```

Install puppet::main with custom parameters:

```puppet
class { '::puppet::main':
  modulepath   => '/opt/modules',
  archive_file => false,
}
```

Create a new stanza with values

```puppet
define ::puppet::config { 'manifests':
  section => 'test',
  value   => '/home/foo/manifests/site.pp',
}
define ::puppet::config { 'modulepath':
  section => 'test',
  value   => '/home/foo/modules',
}
```
