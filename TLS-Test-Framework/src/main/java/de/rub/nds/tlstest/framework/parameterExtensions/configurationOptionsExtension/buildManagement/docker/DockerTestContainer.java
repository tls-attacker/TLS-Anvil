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
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents a DockerContainer used for testing. It runs an http server at
 * [dockerHost]:[mangerPort] used to shutdown it properly or triggering it if it is a client.
 *
 * <p>It stores and can generate a SiteReport (abstract methods).
 *
 * <p>Additionally it keeps track about it usages by providing functions startUsage, stopUsage and
 * isInUse. This can be used to check if the container is currently unused (however the applications
 * must use these functions properly)
 */
public abstract class DockerTestContainer extends DockerContainer {
    private static final Logger LOGGER = LogManager.getLogger();
    protected Integer managerPort;
    protected FeatureExtractionResult feaureExtractionResult;
    protected String dockerHost;
    protected int inUseCount;

    /**
     * Constructor.
     *
     * @param dockerClient - the docker client
     * @param dockerTag - the dockerTag of the image the container is built on
     * @param containerId - the containers id (used to identify the container with the dockerClient)
     * @param dockerHost - the host address the docker container is bound on
     * @param managerPort - the port (on the docker host) the containers manager listens for http
     *     requests (e.g. /trigger)
     */
    public DockerTestContainer(
            DockerClient dockerClient,
            String dockerTag,
            String containerId,
            String dockerHost,
            Integer managerPort) {
        super(dockerTag, containerId, dockerClient);
        this.dockerHost = dockerHost;
        this.managerPort = managerPort;
        this.feaureExtractionResult = null;
        this.inUseCount = 0;
    }

    public String getDockerHost() {
        return dockerHost;
    }

    public Integer getManagerPort() {
        return managerPort;
    }

    /**
     * Send an http request to the manager running within the docker container. (e.g. 'shutdown')
     *
     * @param request - the request to send.
     * @return the manager servers response as a string.
     */
    public String sendHttpRequestToManager(String request) {
        if (this.getContainerState() != DockerContainerState.RUNNING) {
            throw new IllegalStateException(
                    String.format(
                            "Cannot send request to docker container '%s'. Container is in state '%s'.",
                            getDockerTag(), this.getContainerState().toString()));
        }

        String requestHttpUrlString =
                String.format("http://%s:%d/%s", dockerHost, managerPort, request);

        final int MAX_ATTEMPTS = 3;
        final int ATTEMPT_DELAY = 2000; // ms

        boolean connected;
        int attempts = 0;

        URL url;
        try {
            url = new URL(requestHttpUrlString);
        } catch (MalformedURLException e) {
            throw new RuntimeException(
                    String.format("URL '%s' is malformed", requestHttpUrlString));
        }

        String response = "";
        do {
            try {
                HttpURLConnection http = (HttpURLConnection) url.openConnection();
                http.setConnectTimeout(10000);
                int responseCode = http.getResponseCode();

                if (responseCode != 200) {
                    LOGGER.warn(
                            String.format(
                                    "Docker container at '%s' cannot be triggered. Response Code: %d. Try new attempt.",
                                    url, responseCode));
                    connected = false;
                } else {
                    connected = true;
                    // Get the response
                    BufferedReader br =
                            new BufferedReader(new InputStreamReader((http.getInputStream())));
                    StringBuilder sb = new StringBuilder();
                    String output;
                    while ((output = br.readLine()) != null) {
                        sb.append(output);
                    }
                    br.close();
                    response = sb.toString();
                }
                http.disconnect();
            } catch (Exception e) {
                LOGGER.warn(
                        String.format("Client docker container at '%s' cannot be triggered.", url));
                connected = false;
            }
            if (!connected) {
                attempts += 1;
                if (attempts > MAX_ATTEMPTS) {
                    throw new RuntimeException(
                            "Cannot send http request to client docker container.");
                }
                try {
                    Thread.sleep(ATTEMPT_DELAY);
                    LOGGER.warn("Retry...");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } while (!connected);

        return response;
    }

    /**
     * Checks if an application currently registered the usage of this container using startUsage()
     *
     * @return true iff the container is in use
     */
    public boolean isInUse() {
        return (inUseCount > 0);
    }

    /** Registers the start of the usage of this container. */
    public synchronized void startUsage() {
        inUseCount += 1;
    }

    /** Registers the end of the usage of this container. */
    public synchronized void endUsage() {
        inUseCount -= 1;
        if (inUseCount < 0) {
            throw new IllegalStateException(
                    "Negative usage count. Please use 'startUsage()' before calling this method.");
        }
    }

    /**
     * Gets the TestSiteReport for this container. The site report is generated here if it is not
     * created yet.
     *
     * @return the containers TestSiteReport
     */
    public FeatureExtractionResult getFeatureExtractionResult() {
        if (feaureExtractionResult == null) {
            LOGGER.info("Create site report for container with tag '{}'...", this.dockerTag);
            DockerContainerState state = getContainerState();
            startUsage();
            // todo: use one parallelExecutor
            ParallelExecutor parallelExecutor = new ParallelExecutor(1, 2);
            try {
                if (state == DockerContainerState.PAUSED) {
                    unpauseAndWait();
                    feaureExtractionResult = createFeatureExtractionResult(parallelExecutor);
                    pause();
                } else if (state == DockerContainerState.NOT_RUNNING) {
                    startAndWait();
                    feaureExtractionResult = createFeatureExtractionResult(parallelExecutor);
                    stop();
                } else if (state == DockerContainerState.RUNNING) {
                    feaureExtractionResult = createFeatureExtractionResult(parallelExecutor);
                } else {
                    throw new RuntimeException(
                            "Can't create SiteReport in invalid container state.");
                }
            } catch (TimeoutException e) {
                endUsage();
                throw new RuntimeException(
                        "Cannot create site report. Container cannot be started.");
            }
            endUsage();
        }
        return feaureExtractionResult;
    }

    /**
     * Abstract method to create a site report. Note that while this method is called the usage is
     * already registered, and the container is already running.
     *
     * @return the created FeatureExtractionResult
     */
    protected abstract FeatureExtractionResult createFeatureExtractionResult(
            ParallelExecutor parallelExecutor);
}
