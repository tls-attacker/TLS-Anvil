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

    private String managerHost;
    private Integer managerPort;

    public DockerClientContainerInfo(String dockerTag, String containerId, DockerContainerState containerState,
                                     String managerHost, Integer managerPort)
    {
        super(dockerTag, containerId, containerState);

        this.managerHost = managerHost;
        this.managerPort = managerPort;
    }

    public String getManagerHost() {
        return managerHost;
    }

    public void setManagerHost(String managerHost) {
        this.managerHost = managerHost;
    }

    public Integer getManagerPort() {
        return managerPort;
    }

    public void setManagerPort(Integer managerPort) {
        this.managerPort = managerPort;
    }
}
