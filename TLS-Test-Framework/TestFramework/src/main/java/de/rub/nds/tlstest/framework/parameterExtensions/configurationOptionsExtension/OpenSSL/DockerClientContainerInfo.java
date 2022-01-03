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

public class DockerClientContainerInfo extends DockerContainerInfo{

    private String dockerHost;
    private Integer managerPort;

    public DockerClientContainerInfo(String dockerTag, String containerId, DockerContainerState containerState,
                                     String dockerHost, Integer managerPort)
    {
        super(dockerTag, containerId, containerState);

        this.dockerHost = dockerHost;
        this.managerPort = managerPort;
    }

    public String getDockerHost() {
        return dockerHost;
    }

    public void setDockerHost(String dockerHost) {
        this.dockerHost = dockerHost;
    }

    public Integer getManagerPort() {
        return managerPort;
    }

    public void setManagerPort(Integer managerPort) {
        this.managerPort = managerPort;
    }
}
