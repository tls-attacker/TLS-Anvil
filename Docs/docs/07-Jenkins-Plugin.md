# TLS-Anvil Jenkins Plugin

TLS-Anvil offers a Jenkins plugin for seamless integration into CI pipelines.

The plugin repository is available here: [TLS-Anvil-Jenkins](https://github.com/tls-attacker/TLS-Anvil-Jenkins/)

## Version

The plugin version corresponds to the TLS-Anvil version it supports.  
For example, version *v1.4.0-R1* uses TLS-Anvil *1.4.0*.

## Installation

:::info

The Jenkins plugin is currently not distributed through the official Jenkins plugin store. It must be installed manually.

:::

**Prerequisites**

- Ensure the [Docker Commons Plugin](https://plugins.jenkins.io/docker-commons/) is installed and configured for Docker usage.

1. Download the latest release `.hpi` file from the [Releases page](https://github.com/tls-attacker/TLS-Anvil-Jenkins/releases).
2. Open your Jenkins instance.
3. Navigate to **Manage Jenkins > Manage Plugins**.
4. Select the **Advanced** tab.
5. Under the **Upload Plugin** section, click **Choose File** and select the downloaded `.hpi` file.
6. Click **Upload** to install the plugin.
7. Restart Jenkins if prompted.

## Usage

The plugin adds a custom build step to your pipeline. Typically, this step is added after a successful build during the *integration testing phase*.

It requires an executable example server or client implementation that can be started.

For detailed instructions, refer to the plugin’s [README](https://github.com/tls-attacker/TLS-Anvil-Jenkins).

:::tip

We recommend using the `expectedResults` feature, as explained [here](/docs/Advanced-Features/Expected-Results).  
Only use expected results maps that have been manually reviewed.

:::
