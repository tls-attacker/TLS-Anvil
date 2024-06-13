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
import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.*;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.transport.DockerHttpClient;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerTlsInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsClientInstanceBuilder;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsInstanceBuilder;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsServerInstanceBuilder;
import de.rub.nds.tls.subject.docker.build.DockerBuilder;
import de.rub.nds.tls.subject.exceptions.CertVolumeNotFoundException;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import java.util.*;
import java.util.function.Predicate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract factory to create DockerServerTestContainer%s and DockerClientTestContainer%s. Which
 * Dockerfiles of the TLS docker library are used and how and with which arguments the images and
 * containers are created is up to the sub class implementations.
 */
public class DockerFactory {
    private static final int CONTAINER_PORT_TLS_SERVER = 4433;
    private static final int CONTAINER_MANAGER_PORT = 8090;
    private static final Logger LOGGER = LogManager.getLogger();
    private DockerClient dockerClient;
    private final String containerNamePrefix;
    private final TlsImplementationType tlsImplementationType;

    protected Set<String> failedBuildDockerTags;
    protected Set<String> existingDockerImageNameWithTags;

    protected ConfigurationOptionsConfig configOptionsConfig;

    protected DockerBuilder dockerBuilder = new DockerBuilder();

    /**
     * Constructor.
     *
     * @param configurationOptionsConfig - The configuration options config
     */
    public DockerFactory(ConfigurationOptionsConfig configurationOptionsConfig) {
        this.tlsImplementationType =
                TlsImplementationType.valueOf(configurationOptionsConfig.getTlsLibraryName());
        this.containerNamePrefix = "TLS-Anvil-" + tlsImplementationType.name().toLowerCase();
        this.configOptionsConfig = configurationOptionsConfig;
        this.failedBuildDockerTags = new HashSet<>();
    }

    /**
     * Builds a TLS library with the specified cliOptions as build flags
     *
     * @param cliOptions - The list of cliOptions to compile the tls library
     * @param dockerTag - The docker tag the image should have (should be derived from the
     *     cliOptions and the version)
     * @param libraryVersionName - The version of the tls library (e.g. the respective git branch
     *     tag)
     * @param resultsCollector - The result collector to log build and container information
     */
    public boolean buildTlsLibraryDockerImage(
            TlsImplementationType tlsLibrary,
            String version,
            ConnectionRole connectionEndPointToBuild,
            String buildFlags) {
        boolean success =
                buildDockerImage(tlsLibrary, version, connectionEndPointToBuild, buildFlags);
        String dockerNameWithTag =
                DockerBuilder.getDefaultRepoAndTag(
                        tlsLibrary, version, connectionEndPointToBuild, buildFlags);
        if (success) {
            existingDockerImageNameWithTags.add(dockerNameWithTag);
        } else {
            failedBuildDockerTags.add(dockerNameWithTag);
        }
        return success;
    }

    /**
     * Builds a docker image using the TLS-Docker-Library
     *
     * @param tlsLibrary The TLS library to build. Must be listed in the docker library's json
     *     files.
     * @param version The version to build. Must be listed in the docker library's json files.
     * @param connectionEndPointToBuild The connection end point of the image.
     * @param buildFlags The build flags to apply during build. Must be supported by the respective
     *     dockerfile in the docker library.
     * @return true if successfull, false otherwise
     */
    protected boolean buildDockerImage(
            TlsImplementationType tlsLibrary,
            String version,
            ConnectionRole connectionEndPointToBuild,
            String buildFlags) {
        try {
            dockerBuilder.buildLibraryImage(
                    tlsLibrary, version, connectionEndPointToBuild, buildFlags);
        } catch (Exception ex) {
            LOGGER.error(ex);
            return false;
        }
        if (DockerBuilder.getBuiltImage(tlsLibrary, version, connectionEndPointToBuild, buildFlags)
                != null) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Create a DockerClientTestContainer using the respective configurations. An image for the
     * respective docker tag must exist otherwise it will fail.
     *
     * @param tlsImplementationType The TLS library to start
     * @param version The version of the library to start
     * @param buildFlags The build flags that must be set for the library image
     * @param dockerManagerHost The host address the docker container is bound on
     * @param dockerManagerPort The port (on the docker host) the containers manager listens for
     * @param tlsServerHost The server host the client connects to
     * @param tlsServerPort The server port the client connects to
     * @return The created DockerClientTestContainer instance
     */
    public DockerClientTestContainer createDockerClient(
            TlsImplementationType tlsImplementationType,
            String version,
            String buildFlags,
            String dockerManagerHost,
            Integer dockerManagerPort,
            String tlsServerHost,
            Integer tlsServerPort) {

        String dockerTag =
                DockerBuilder.getDefaultTag(
                        tlsImplementationType, version, ConnectionRole.CLIENT, buildFlags);
        List<PortBinding> portBindings = new LinkedList<>();

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerManagerPort),
                        exposedManagerPort));

        String containerName = String.format("%s_client_%s", containerNamePrefix, dockerTag);
        TransportType clientTransportType;
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            clientTransportType = TransportType.UDP;
        } else {
            clientTransportType = TransportType.TCP;
        }
        TlsClientInstanceBuilder clientInstanceBuilder =
                new TlsClientInstanceBuilder(tlsImplementationType, version, clientTransportType)
                        .hostname(tlsServerHost)
                        .port(tlsServerPort)
                        .additionalBuildFlags(buildFlags);

        String dockerContainerId =
                createDockerContainer(clientInstanceBuilder, portBindings, containerName);

        return new DockerClientTestContainer(
                dockerClient,
                dockerTag,
                dockerContainerId,
                dockerManagerHost,
                dockerManagerPort,
                configOptionsConfig.getDockerClientDestinationHostName(),
                tlsServerPort);
    }

    /**
     * Create a DockerServerTestContainer using the respective configurations. An image for the
     * respective docker tag must exist otherwise it will fail.
     *
     * @param tlsImplementationType The TLS library to start
     * @param version The version of the library to start
     * @param buildFlags The build flags that must be set for the library image
     * @param dockerHost The host address the docker container is bound on
     * @param dockerManagerPort The port (on the docker host) the containers manager listens for
     * @param dockerTlsPort The exposed port of the TLS server
     * @return
     */
    public DockerServerTestContainer createDockerServer(
            TlsImplementationType tlsImplementationType,
            String version,
            String buildFlags,
            String dockerHost,
            Integer dockerManagerPort,
            Integer dockerTlsPort) {
        List<PortBinding> portBindings = new LinkedList<>();

        String dockerTag =
                DockerBuilder.getDefaultTag(
                        tlsImplementationType, version, ConnectionRole.SERVER, buildFlags);
        ExposedPort exposedTlsServerPort = ExposedPort.tcp(CONTAINER_PORT_TLS_SERVER);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerTlsPort),
                        exposedTlsServerPort));

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerManagerPort),
                        exposedManagerPort));
        TransportType serverTransportType;
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            serverTransportType = TransportType.UDP;
        } else {
            serverTransportType = TransportType.TCP;
        }
        TlsServerInstanceBuilder tlsServerInstanceBuilder =
                new TlsServerInstanceBuilder(tlsImplementationType, version, serverTransportType)
                        .hostname(dockerHost)
                        .port(CONTAINER_PORT_TLS_SERVER)
                        .additionalBuildFlags(buildFlags);

        String containerName = String.format("%s_server_%s", containerNamePrefix, dockerTag);
        String dockerContainerId =
                createDockerContainer(tlsServerInstanceBuilder, portBindings, containerName);

        return new DockerServerTestContainer(
                dockerClient,
                dockerTag,
                dockerContainerId,
                dockerHost,
                dockerManagerPort,
                dockerTlsPort);
    }

    /**
     * Initializes the docker factory (e.g. create base builds, etc.). Must be called before any
     * images are build using the other functions.
     */
    public void init() {
        List<Image> imageList;
        try {
            DefaultDockerClientConfig config =
                    DefaultDockerClientConfig.createDefaultConfigBuilder().build();

            DockerHttpClient httpClient =
                    (new com.github.dockerjava.jaxrs.JerseyDockerHttpClient.Builder())
                            .dockerHost(config.getDockerHost())
                            .sslConfig(config.getSSLConfig())
                            .build();

            this.dockerClient =
                    DockerClientBuilder.getInstance(config)
                            .withDockerHttpClient(httpClient)
                            .build();

            imageList = dockerClient.listImagesCmd().withDanglingFilter(false).exec();
        } catch (Exception e) {
            LOGGER.error(
                    "Cannot initialize the docker client. Is docker installed and started?", e);
            throw new RuntimeException("Cannot initialize docker.");
        }

        // Get all existing docker tags
        // Note that it is assumed, that no (relevant) docker images are created or deleted manually
        // during the test executions
        existingDockerImageNameWithTags = new HashSet<>();
        for (Image img : imageList) {
            Object tagsObj = img.getRawValues().get("RepoTags");
            if (!(tagsObj instanceof List<?>)) {
                throw new RuntimeException("Cannot get repoTags");
            }
            try {
                @SuppressWarnings("unchecked")
                List<String> tags = (List<String>) tagsObj;
                existingDockerImageNameWithTags.addAll(tags);
            } catch (ClassCastException e) {
                LOGGER.error(e);
                throw new RuntimeException("Failed to get current docker images.");
            }
        }

        try {
            DockerBuilder.getCertDataVolumeInfo();
        } catch (CertVolumeNotFoundException ex) {
            throw new RuntimeException(
                    "Docker library's certificate volume not found. The docker library must be initialized through its setup script first.");
        }
    }

    /**
     * Creates a docker container and returns the container id of the created container.
     *
     * @param dockerImageTag - the tag of the docker image to create the build from
     * @param entrypoint - the entrypoint to use
     * @param portBindings - the port bindings
     * @param volumeBindings - the volume bindings
     * @return the container id
     */
    public synchronized String createDockerContainer(
            TlsInstanceBuilder tlsInstanceBuilder,
            List<PortBinding> portBindings,
            String containerName) {

        Optional<Container> oldContainer = containerByName(containerName);
        if (oldContainer.isPresent()) {
            dockerClient.removeContainerCmd(oldContainer.get().getId()).withForce(true).exec();
            LOGGER.debug("Old Container Removed");
        }

        List<ExposedPort> exposedPorts = new LinkedList<>();
        for (PortBinding portBinding : portBindings) {
            exposedPorts.add(portBinding.getExposedPort());
        }
        try {
            DockerTlsInstance dockerTlsInstance =
                    tlsInstanceBuilder
                            .hostConfigHook(
                                    config -> {
                                        return ((HostConfig) config)
                                                .withPortBindings(portBindings)
                                                .withDns(new ArrayList<>())
                                                .withDnsOptions(new ArrayList<>())
                                                .withDnsSearch(new ArrayList<>())
                                                .withBlkioWeightDevice(new ArrayList<>())
                                                .withDevices(new ArrayList<>())
                                                .withExtraHosts(
                                                        "host.docker.internal:host-gateway");
                                    })
                            .containerName(containerName)
                            .containerExposedPorts(exposedPorts)
                            .build();
            dockerTlsInstance.ensureContainerExists();
            return dockerTlsInstance.getId();
        } catch (DockerException | InterruptedException e) {
            LOGGER.error(e);
            return null;
        }
    }

    public boolean buildFailedForRepoTag(String repoTag) {
        return this.failedBuildDockerTags.contains(repoTag);
    }

    /**
     * Gets the dockerClient this factory uses (created automatically in init).
     *
     * @return the DockerClient
     */
    public DockerClient getDockerClient() {
        return dockerClient;
    }

    protected Optional<Container> containerByName(String name) {
        final String cName;
        if (!name.startsWith("/")) {
            cName = "/" + name;
        } else {
            cName = name;
        }
        Predicate<Container> pred =
                container -> Arrays.asList(container.getNames()).contains(cName);
        return dockerClient.listContainersCmd().withShowAll(true).exec().stream()
                .filter(pred)
                .findFirst();
    }

    /**
     * Checks if and image of the specified image exists. (Does not catch any shenanigans with
     * docker (e.g. manual deletions) during the execution)
     *
     * @param dockerTag - The docker image tag
     * @return true iff the docker image exists
     */
    public boolean dockerNameWithTagExists(String dockerTag) {
        return existingDockerImageNameWithTags.contains(dockerTag);
    }
}
