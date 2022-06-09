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
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.DockerContainerLogFile;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.util.concurrent.TimeoutException;

/**
 * Represents a single docker container. A docker container is identified by the tag of the image it was created with
 * (which is unique for ever parameter combination). Also it has a container id that is used to access it via the DockerClient.
 * An instance of the dockerClient has to be passed to enable controlling feature of the container like starting, stopping and
 * removing the container.
 *
 * The state of the container is cached and can be accessed via the getContainerState method. HOWEVER, THIS STATE IS NOT
 * NECESSARILY THE REAL STATE OF THE CONTAINER. To minimize the amount of requests to the docker client it is only the
 * state the container should be in using the controlling functions. To get and update the ACTUAL state, run the
 * updateContainerState() function which requests the dockerClient for the real state.
 */
public class DockerContainer {
    private static final Logger LOGGER = LogManager.getLogger();

    protected String dockerTag;
    protected String containerId;
    protected DockerContainerState containerState;
    protected DockerClient dockerClient;
    protected DockerContainerLogFile containerLogger;

    /**
     * Constructor.
     *
     * @param dockerClient - the docker client
     * @param dockerTag - the dockerTag of the image the container is built on
     * @param containerId - the containers id (used to identify the container with the dockerClient)
     */
    public DockerContainer(String dockerTag, String containerId, DockerClient dockerClient) {
        this.dockerClient = dockerClient;
        this.dockerTag = dockerTag;
        this.containerId = containerId;
        this.containerState = updateContainerState();
        containerLogger = null;
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

    public DockerClient getDockerClient() {
        return dockerClient;
    }

    public DockerContainerLogFile enableContainerLogging(ConfigOptionsResultsCollector resultsCollector, String category){
        containerLogger = resultsCollector.logContainer(this, category);
        return containerLogger;
    }

    /**
     * Requests the dockerClient for the real state the container is in. Updates the cached state
     * accordingly.
     *
     * @returns the real state the container is currently in.
     */
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

    // Management

    /**
     * Starts a stopped container.
     */
    public synchronized void start(){
        if(this.getContainerState() != DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot start a running (or paused) container.");
        }
        dockerClient.startContainerCmd(this.getContainerId()).exec();
        if(containerLogger != null){
            containerLogger.notifyContainerStart();
        }
        this.containerState = DockerContainerState.RUNNING;
    }

    /**
     * Starts a stopped container and waits for the container to reach the real state RUNNING. A TimeoutException
     * is thrown if the container does not reach this state in 30 sec.
     *
     * @throws TimeoutException
     */
    public synchronized void startAndWait() throws TimeoutException {
        this.start();

        waitForState(DockerContainerState.RUNNING, 30000);
    }

    /**
     * Stops a running container.
     */
    public synchronized void stop(){
        if(this.getContainerState() == DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot stop a stopped container.");
        }
        dockerClient.stopContainerCmd(this.getContainerId()).exec();
        this.containerState =DockerContainerState.NOT_RUNNING;
    }

    /**
     * Pauses a running container.
     */
    public synchronized void pause(){
        if(this.getContainerState() != DockerContainerState.RUNNING){
            throw new IllegalStateException("Cannot pause a non running container.");
        }
        dockerClient.pauseContainerCmd(this.getContainerId()).exec();
        this.containerState = DockerContainerState.PAUSED;
    }

    /**
     * Unpauses a paused container.
     */
    public synchronized void unpause(){
        if(this.getContainerState() != DockerContainerState.PAUSED){
            throw new IllegalStateException("Cannot unpause a non paused container.");
        }
        dockerClient.unpauseContainerCmd(this.getContainerId()).exec();
        this.containerState = DockerContainerState.RUNNING;
    }

    /**
     * Unpauses a paused container and waits for the container to reach the real state RUNNING. A TimeoutException
     * is thrown if the container does not reach this state in 30 sec.
     *
     * @throws TimeoutException
     */
    public synchronized void unpauseAndWait() throws TimeoutException {
        unpause();
        waitForState(DockerContainerState.PAUSED, 30000);
    }

    /**
     * Removes the container. Afterwards the container is in the invalid state and cannot be used anymore.
     */
    public synchronized void remove(){
        dockerClient.removeContainerCmd(this.getContainerId()).withForce(true).exec();
        this.containerState = DockerContainerState.INVALID;
    }

    /**
     * Waits until the container reaches the REAL defined state. Throws a timeout exception if the state is not
     * reached within timeoutMs seconds.
     *
     * Note that this function does not actively change the state. It should be only called if a state change can
     * be expected.
     *
     * @param state - the state to wait for
     * @param timeoutMs - the maximal waiting time in ms.
     * @throws TimeoutException
     */
    public synchronized void waitForState(DockerContainerState state, int timeoutMs) throws TimeoutException {
        final long CHECK_INTERVAL = 200; // 0.2 sec

        long timeoutCtr = 0;
        do {
            if(this.updateContainerState() == state){
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
                if(timeoutCtr > timeoutMs){
                    throw new TimeoutException(String.format("Timeout (%d ms) while waiting for container '%s' to reach state %s.", timeoutMs ,this.getDockerTag(), state.toString()));
                }
            }
        } while(true);
    }
}
