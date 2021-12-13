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

public class DockerServerContainerInfo extends DockerContainerInfo{
    private String tlsServerHost;
    private Integer tlsServerPort;

    public DockerServerContainerInfo(String dockerTag, String containerId, DockerContainerState containerState, String tlsServerHost, Integer tlsServerPort) {
        super(dockerTag, containerId, containerState);
        this.tlsServerHost = tlsServerHost;
        this.tlsServerPort = tlsServerPort;
    }

    public String getTlsServerHost() {
        return tlsServerHost;
    }

    public void setTlsServerHost(String tlsServerHost) {
        this.tlsServerHost = tlsServerHost;
    }

    public Integer getTlsServerPort() {
        return tlsServerPort;
    }

    public void setTlsServerPort(Integer tlsServerPort) {
        this.tlsServerPort = tlsServerPort;
    }


}
