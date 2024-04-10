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
import com.github.dockerjava.api.exception.NotModifiedException;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.DockerContainerLogFile;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents a single docker container. A docker container is identified by the tag of the image it
 * was created with (which is unique for ever parameter combination). Also it has a container id
 * that is used to access it via the DockerClient. An instance of the dockerClient has to be passed
 * to enable controlling feature of the container like starting, stopping and removing the
 * container.
 *
 * <p>The state of the container is cached and can be accessed via the getContainerState method.
 * HOWEVER, THIS STATE IS NOT NECESSARILY THE REAL STATE OF THE CONTAINER. To minimize the amount of
 * requests to the docker client it is only the state the container should be in using the
 * controlling functions. To get and update the ACTUAL state, run the updateContainerState()
 * function which requests the dockerClient for the real state.
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

    public DockerContainerLogFile enableContainerLogging(
            ConfigOptionsResultsCollector resultsCollector, String category, String name) {
        containerLogger = resultsCollector.logContainer(this, category, name);
        return containerLogger;
    }

    /**
     * Requests the dockerClient for the real state the container is in. Updates the cached state
     * accordingly.
     *
     * @return the real state the container is currently in.
     */
    public DockerContainerState updateContainerState() {
        InspectContainerResponse containerResp =
                dockerClient.inspectContainerCmd(this.getContainerId()).exec();
        InspectContainerResponse.ContainerState state = containerResp.getState();
        if (containerState == DockerContainerState.INVALID) {
            return DockerContainerState.INVALID;
        }
        if (state.getRunning() != null && state.getRunning()) {
            this.containerState = DockerContainerState.RUNNING;
            return DockerContainerState.RUNNING;
        } else if (state.getPaused() != null && state.getPaused()) {
            this.containerState = DockerContainerState.PAUSED;
            return DockerContainerState.PAUSED;
        } else {
            this.containerState = DockerContainerState.NOT_RUNNING;
            return DockerContainerState.NOT_RUNNING;
        }
    }

    // Management

    /** Starts a stopped container. */
    public synchronized void start() {
        if (this.getContainerState() != DockerContainerState.NOT_RUNNING) {
            throw new IllegalStateException("Cannot start a running (or paused) container.");
        }
        try {
            dockerClient.startContainerCmd(this.getContainerId()).exec();
        } catch (NotModifiedException e) {
            LOGGER.warn(
                    "Got unexpected state (RUNNING) of docker container while trying to start it.");
        }

        if (containerLogger != null) {
            containerLogger.notifyContainerStart();
        }
        this.containerState = DockerContainerState.RUNNING;
    }

    /**
     * Starts a stopped container and waits for the container to reach the real state RUNNING. A
     * TimeoutException is thrown if the container does not reach this state in 30 sec.
     */
    public synchronized void startAndWait() throws TimeoutException {
        final int WAIT_AFTER_STARTED = 1000;
        this.start();
        waitForState(DockerContainerState.RUNNING, 30000);
        // Wait some time so the server/client has time to get ready (cannot by requested from
        // docker)
        try {
            Thread.sleep(WAIT_AFTER_STARTED);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /** Stops a running container. */
    public synchronized void stop() {
        if (this.getContainerState() == DockerContainerState.NOT_RUNNING) {
            throw new IllegalStateException("Cannot stop a stopped container.");
        }
        try {
            dockerClient.stopContainerCmd(this.getContainerId()).exec();
        } catch (NotModifiedException e) {
            LOGGER.warn(
                    "Got unexpected state (NOT_RUNNING) of docker container while trying to stop it.");
        }
        this.containerState = DockerContainerState.NOT_RUNNING;
    }

    /** Pauses a running container. */
    public synchronized void pause() {
        if (this.getContainerState() != DockerContainerState.RUNNING) {
            throw new IllegalStateException("Cannot pause a non running container.");
        }
        try {
            dockerClient.pauseContainerCmd(this.getContainerId()).exec();
        } catch (NotModifiedException e) {
            LOGGER.warn(
                    "Got unexpected state (PAUSED) of docker container while trying to pause it.");
        }
        this.containerState = DockerContainerState.PAUSED;
    }

    /** Unpauses a paused container. */
    public synchronized void unpause() {
        if (this.getContainerState() != DockerContainerState.PAUSED) {
            throw new IllegalStateException("Cannot unpause a non paused container.");
        }
        try {
            dockerClient.unpauseContainerCmd(this.getContainerId()).exec();
        } catch (NotModifiedException e) {
            LOGGER.warn(
                    "Got unexpected state (RUNNING) of docker container while trying to unpause it.");
        }
        this.containerState = DockerContainerState.RUNNING;
    }

    /**
     * Unpauses a paused container and waits for the container to reach the real state RUNNING. A
     * TimeoutException is thrown if the container does not reach this state in 30 sec.
     */
    public synchronized void unpauseAndWait() throws TimeoutException {
        unpause();
        waitForState(DockerContainerState.PAUSED, 30000);
    }

    /**
     * Removes the container. Afterwards the container is in the invalid state and cannot be used
     * anymore.
     */
    public synchronized void remove() {
        dockerClient.removeContainerCmd(this.getContainerId()).withForce(true).exec();
        this.containerState = DockerContainerState.INVALID;
    }

    /**
     * Waits until the container reaches the REAL defined state. Throws a timeout exception if the
     * state is not reached within timeoutMs seconds.
     *
     * <p>Note that this function does not actively change the state. It should be only called if a
     * state change can be expected.
     *
     * @param state - the state to wait for
     * @param timeoutMs - the maximal waiting time in ms.
     */
    public synchronized void waitForState(DockerContainerState state, int timeoutMs)
            throws TimeoutException {
        final long CHECK_INTERVAL = 200; // 0.2 sec

        long timeoutCtr = 0;
        do {
            if (this.updateContainerState() == state) {
                break;
            } else {
                try {
                    TimeUnit.MILLISECONDS.sleep(CHECK_INTERVAL);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                timeoutCtr += CHECK_INTERVAL;
                if (timeoutCtr > timeoutMs) {
                    throw new TimeoutException(
                            String.format(
                                    "Timeout (%d ms) while waiting for container '%s' to reach state %s.",
                                    timeoutMs, this.getDockerTag(), state.toString()));
                }
            }
        } while (true);
    }
}
