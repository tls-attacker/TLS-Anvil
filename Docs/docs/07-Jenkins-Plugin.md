# TLS-Anvil Jenkins Plugin

TLS-Anvil provides a Jenkins plugin for easy integration in CI pipelines.

The plugin can be found here: [TLS-Anvil-Jenkins](https://github.com/tls-attacker/TLS-Anvil-Jenkins/)

## Version

The plugin follows TLS-Anvil versions, with the main version of TLS-Anvil in the plugin version name.
E.g. version *v1.3.1-R1* uses TLS-Anvil *1.3.1*.

## Install

:::info

The Jenkins plugin is not distributed through the official Jenkins store for now. You have to manually install it.

:::

**Prerequisites**

- Make sure you have the [Docker Commons Plugin](https://plugins.jenkins.io/docker-commons/) installed and set up for use with docker.

1. Download the newest release version `.hpi` file from the [Releases Site](https://github.com/tls-attacker/TLS-Anvil-Jenkins/releases)
2. Open your Jenkins instance. 
3. Navigate to Manage Jenkins > Manage Plugins. 
4. Go to the Advanced tab. 
5. Under the Upload Plugin section, click on Choose File and select the downloaded HPI file. 
6. Click on Upload to install the plugin. 
7. Restart Jenkins if prompted.

## Usage

The plugin provides a custom build step that you can include in your build pipeline. Usually one would put that build step after the successful build in the *integration testing phase*. 

The plugin requires an executable example server or client implementation, that can be started.

Consult the plugins [README](https://github.com/tls-attacker/TLS-Anvil-Jenkins) page for detailed instructions.

:::tip

It is recommended to use the `expectedResults` feature, as described [here](/docs/Advanced-Features/Expected-Results).
Only use expected results maps, that you manually reviewed before.

:::
