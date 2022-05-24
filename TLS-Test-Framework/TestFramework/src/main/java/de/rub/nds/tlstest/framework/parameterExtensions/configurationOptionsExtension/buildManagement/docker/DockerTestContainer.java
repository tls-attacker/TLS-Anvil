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
import com.github.dockerjava.api.command.InspectContainerResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class is used to store information regarding docker containers. It is faster to store these information
 * than to perform a docker inspect container command every time.
 */
public class DockerTestContainer {
    private static final Logger LOGGER = LogManager.getLogger();
    private String dockerTag;
    private String containerId;
    private DockerContainerState containerState;
    private DockerClient dockerClient;
    // -1 if there is no manager port
    private Integer managerPort;



    public DockerTestContainer(DockerClient dockerClient, String dockerTag, String containerId, Integer managerPort){
        this.dockerTag = dockerTag;
        this.containerId = containerId;
        this.containerState = containerState;
        this.dockerClient = dockerClient;
        this.managerPort = managerPort;
        updateContainerState();
    }

    public DockerTestContainer(DockerClient dockerClient, String dockerTag, String containerId){
        this(dockerClient, dockerTag, containerId, -1);
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

    public DockerContainerState updateContainerState() {
        InspectContainerResponse containerResp = dockerClient.inspectContainerCmd(this.getContainerId()).exec();
        InspectContainerResponse.ContainerState state = containerResp.getState();
        if(containerState == DockerContainerState.INVALID){
            return DockerContainerState.INVALID;
        }
        if(state.getRunning()){
            this.containerState = DockerContainerState.RUNNING;
            return DockerContainerState.RUNNING;
        }
        else if(state.getPaused()){
            this.containerState = DockerContainerState.PAUSED;
            return DockerContainerState.PAUSED;
        }
        else{
            this.containerState = DockerContainerState.NOT_RUNNING;
            return DockerContainerState.NOT_RUNNING;
        }
    }

    public Integer getManagerPort() { return managerPort; }


    // Management
    public void start(){
        if(this.getContainerState() != DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot start a running (or paused) container.");
        }
        dockerClient.startContainerCmd(this.getContainerId()).exec();
        this.containerState = DockerContainerState.RUNNING;
    }

    public void startAndWait() {
        this.start();

        final long CHECK_INTERVAL = 200; // 0.2 sec
        final long TIMEOUT_AFTER = 30000; // 30 sec
        InspectContainerResponse containerResp;
        long timeoutCtr = 0;
        do {
            containerResp = dockerClient.inspectContainerCmd(this.getContainerId()).exec();
            if(containerResp.getState().getRunning() == true){
                break;
            }
            else{
                try{
                    Thread.sleep(CHECK_INTERVAL);
                }
                catch (InterruptedException e) {
                    e.printStackTrace();
                }
                timeoutCtr+=CHECK_INTERVAL;
                if(timeoutCtr > TIMEOUT_AFTER){
                    LOGGER.error(String.format("Cannot start container with tag '%s'", this.getDockerTag()));
                    break;
                }
            }
        } while(true);
    }

    public void stop(){
        if(this.getContainerState() == DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot stop a stopped container.");
        }
        dockerClient.stopContainerCmd(this.getContainerId()).exec();
        this.containerState =DockerContainerState.NOT_RUNNING;
    }

    public void pause(){
        if(this.getContainerState() != DockerContainerState.RUNNING){
            throw new IllegalStateException("Cannot pause a non running container.");
        }
        dockerClient.pauseContainerCmd(this.getContainerId()).exec();
        this.containerState = DockerContainerState.PAUSED;
    }

    public void unpause(){
        if(this.getContainerState() != DockerContainerState.PAUSED){
            throw new IllegalStateException("Cannot unpause a non paused container.");
        }
        dockerClient.unpauseContainerCmd(this.getContainerId()).exec();
        this.containerState = DockerContainerState.RUNNING;
    }

    // Unpauses the container and sleeps to give the container time to unpause
    public void unpauseAndWait() {
        unpause();

        final long CHECK_INTERVAL = 200; // 0.2 sec
        final long TIMEOUT_AFTER = 30000; // 30 sec
        InspectContainerResponse containerResp;
        long timeoutCtr = 0;
        do {
            containerResp = dockerClient.inspectContainerCmd(this.getContainerId()).exec();
            if(containerResp.getState().getPaused() == false){
                break;
            }
            else{
                try{
                    Thread.sleep(CHECK_INTERVAL);
                }
                catch (InterruptedException e) {
                    e.printStackTrace();
                }
                timeoutCtr+=CHECK_INTERVAL;
                if(timeoutCtr > TIMEOUT_AFTER){
                    LOGGER.error(String.format("Cannot unpause container with tag '%s'", this.getDockerTag()));
                    break;
                }
            }
        } while(true);
    }

    public void remove(){
        dockerClient.removeContainerCmd(this.getContainerId()).withForce(true).exec();
        this.containerState = DockerContainerState.INVALID;
    }

}