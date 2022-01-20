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
 * This private class is used to store information regarding docker containers. It is faster to store these information
 * than to perform a docker inspect container command every time.
 */
public class DockerContainerInfo {
    private String dockerTag;
    private String containerId;
    private DockerContainerState containerState;


    public DockerContainerInfo(String dockerTag, String containerId, DockerContainerState containerState){
        this.dockerTag = dockerTag;
        this.containerId = containerId;
        this.containerState = containerState;
    }

    public String getDockerTag() {
        return dockerTag;
    }

    public String getContainerId() {
        return containerId;
    }

    public DockerContainerState getContainerState() {
        return containerState;
    }

    public void updateContainerState(DockerContainerState containerState) {
        this.containerState = containerState;
    }

}