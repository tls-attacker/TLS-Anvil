/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker;

import com.github.dockerjava.api.DockerClient;

/**
 * Info of a DockerContainer that runs tls clients for testing purposes.
 * The dockerHost is the host address the docker containers ports are bound to.
 * The managerPort is the host's port on which the docker container's http server listens for the /trigger and /shutdown command.
 */
public class DockerClientTestContainer extends DockerTestContainer {

    private String dockerHost;
    private Integer inboundConnectionPort;

    public DockerClientTestContainer(DockerClient dockerClient, String dockerTag, String containerId,
                                     String dockerHost, Integer managerPort, Integer inboundConnectionPort)
    {
        super(dockerClient, dockerTag, containerId, managerPort);

        this.dockerHost = dockerHost;
        this.inboundConnectionPort = inboundConnectionPort;
    }

    public String getDockerHost() {
        return dockerHost;
    }

    public void setDockerHost(String dockerHost) {
        this.dockerHost = dockerHost;
    }

    public Integer getInboundConnectionPort() {
        return inboundConnectionPort;
    }

    public void setInboundConnectionPort(Integer inboundConnectionPort) {
        this.inboundConnectionPort = inboundConnectionPort;
    }
}
