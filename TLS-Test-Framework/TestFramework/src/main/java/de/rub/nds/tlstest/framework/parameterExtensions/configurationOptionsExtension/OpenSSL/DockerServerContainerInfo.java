/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL;

/**
 * Info of a DockerContainer that runs a tls server for testing purposes.
 * The dockerHost is the host address the docker containers ports are bound to.
 * The tlsServerPort is the host's port on which the tls server is available.
 * The managerPort is the host's port on which the docker container's http server listens for the /shutdown command.
 */
public class DockerServerContainerInfo extends DockerContainerInfo{
    private String dockerHost;
    private Integer tlsServerPort;
    private Integer managerPort;

    public DockerServerContainerInfo(String dockerTag, String containerId, DockerContainerState containerState, String dockerHost, Integer tlsServerPort, Integer managerPort) {
        super(dockerTag, containerId, containerState);
        this.dockerHost = dockerHost;
        this.tlsServerPort = tlsServerPort;
        this.managerPort = managerPort;
    }

    public String getDockerHost() {
        return dockerHost;
    }

    public void setDockerHost(String dockerHost) {
        this.dockerHost = dockerHost;
    }

    public Integer getTlsServerPort() {
        return tlsServerPort;
    }

    public void setTlsServerPort(Integer tlsServerPort) {
        this.tlsServerPort = tlsServerPort;
    }

    public Integer getManagerPort() {
        return managerPort;
    }

    public void setManagerPort(Integer managerPort) {
        this.managerPort = managerPort;
    }


}
