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
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.model.*;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.transport.DockerHttpClient;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsMetadataResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Predicate;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract factory to create DockerServerTestContainer%s and DockerClientTestContainer%s. Which
 * Dockerfiles of the TLS docker library are used and how and with which arguments the images and
 * containers are created is up to the sub class implementations.
 */
public abstract class DockerFactory {
    private static final Logger LOGGER = LogManager.getLogger();
    protected DockerClient dockerClient;
    protected String BUILD_REPRO_NAME;
    protected String CONTAINER_NAME_PREFIX;

    protected Set<String> failedBuildDockerTags;
    protected Set<String> existingDockerImageNameWithTags;

    protected ConfigurationOptionsConfig configOptionsConfig;

    /**
     * Constructor.
     *
     * @param configurationOptionsConfig - The configuration options config
     * @param buildReproName - The repository name the images should have.
     */
    public DockerFactory(
            ConfigurationOptionsConfig configurationOptionsConfig, String buildReproName) {
        this.BUILD_REPRO_NAME = buildReproName;
        this.CONTAINER_NAME_PREFIX = "container";
        this.configOptionsConfig = configurationOptionsConfig;
        this.failedBuildDockerTags = new HashSet<>();
    }

    /**
     * Given a set of cliOptions this function builds a build image that utilized the cliOptions for
     * building.
     *
     * @param cliOptions - The list of cliOptions to compile the tls library
     * @param dockerTag - The docker tag the image should have (should be derived from the
     *     cliOptions and the version)
     * @param libraryVersionName - The version of the tls library (e.g. the respective git branch
     *     tag)
     * @param resultsCollector - The result collector to log build and container information
     */
    public boolean buildTlsLibraryDockerImage(
            List<String> cliOptions,
            String dockerTag,
            String libraryVersionName,
            ConfigOptionsMetadataResultsCollector resultsCollector) {
        boolean success =
                buildDockerImage(cliOptions, dockerTag, libraryVersionName, resultsCollector);
        String dockerNameWithTag = this.getBuildImageNameAndTag(dockerTag);
        if (success) {
            existingDockerImageNameWithTags.add(dockerNameWithTag);
        } else {
            failedBuildDockerTags.add(dockerNameWithTag);
        }
        return success;
    }

    /**
     * Given a set of cliOptions this function builds a build image that utilized the cliOptions for
     * building. The actual procedure is up to the subclasses.
     *
     * @param cliOptions - The list of cliOptions to compile the tls library
     * @param dockerTag - The docker tag the image should have (should be derived from the
     *     cliOptions and the version)
     * @param libraryVersionName - The version of the tls library (e.g. the respective git branch
     *     tag)
     * @param resultsCollector - The result collector to log build and container information
     * @return true iff the image was successfully built. If false is returned no image was created
     *     (not even an invalid one)
     */
    protected abstract boolean buildDockerImage(
            List<String> cliOptions,
            String dockerTag,
            String libraryVersionName,
            ConfigOptionsMetadataResultsCollector resultsCollector);

    /**
     * Create a DockerClientTestContainer using the respective configurations. An image for the
     * respective docker tag must exist otherwise it will fail.
     *
     * @param dockerTag - The docker tag of the image the container is derived from
     * @param dockerManagerHost - the host address the docker container is bound on
     * @param dockerManagerPort - the port (on the docker host) the containers manager listens for
     *     http requests (e.g. 'trigger')
     * @param tlsServerHost - the server host the client connects to
     * @param tlsServerPort - the sever port the client connects to
     * @return the DockerClientTestContainer of the already built docker container
     */
    public abstract DockerClientTestContainer createDockerClient(
            String dockerTag,
            String dockerManagerHost,
            Integer dockerManagerPort,
            String tlsServerHost,
            Integer tlsServerPort);

    /**
     * Create a DockerServerTestContainer using the respective configurations. An image for the
     * respective docker tag must exist otherwise it will fail.
     *
     * @param dockerTag - The docker tag of the image the container is derived from
     * @param dockerManagerHost - the host address the docker container is bound on
     * @param dockerManagerPort - the port (on the docker host) the containers manager listens for
     *     http requests (e.g. 'shutdown')
     * @param dockerTlsPort - the port (on the docker host) the tls server runs on
     * @return the DockerServerTestContainer of the already built docker container
     */
    public abstract DockerServerTestContainer createDockerServer(
            String dockerTag,
            String dockerManagerHost,
            Integer dockerManagerPort,
            Integer dockerTlsPort);

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

        // Find dockerfile paths
        Path dockerLibraryPath = configOptionsConfig.getDockerLibraryPath();
        if (!Files.exists(dockerLibraryPath)) {
            throw new RuntimeException(
                    String.format(
                            "Docker library path '%s' does not exist. Have you configured the right Docker Library path?",
                            dockerLibraryPath.toAbsolutePath()));
        }
    }

    /*--------------------
       Utility Functions
    ---------------------*/
    public String getBuildImageNameAndTag(String dockerTag) {
        return String.format("%s:%s", BUILD_REPRO_NAME, dockerTag);
    }

    /**
     * Creates a docker tag. This tag is different, if the library name, the library version, or the
     * cli option string is different. The docker tags looks like: _[LIB NAME]_[LIB VERSION]_[CLI
     * OPTION HASH]
     *
     * <p>the CLI_OPTION HASH is an hex string of the hash value over the cli option input string
     * (required, because the docker tag has a maximal length). Also, both LIB NAME and LIB VERSION
     * are cut after the 20th character and illegal docker tag characters are eliminated.
     *
     * @param cliOptions - The command line string that is passed the buildscript
     * @param libraryNameAndVersion - The library's version (e.g. '1.1.1e')
     * @return the resulting docker tag
     */
    public String computeDockerTag(List<String> cliOptions, String libraryNameAndVersion) {
        String cliString = String.join("", cliOptions);
        String libraryVersionPart =
                libraryNameAndVersion.substring(0, Math.min(20, libraryNameAndVersion.length()));
        String cliStringHashString;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(cliString.getBytes());
            cliStringHashString =
                    DatatypeConverter.printHexBinary(messageDigest.digest()).toLowerCase();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new UnsupportedOperationException("Cannot create a docker tag.");
        }

        cliStringHashString =
                cliStringHashString.substring(0, Math.min(16, cliStringHashString.length()));

        String res = String.format("_%s_%s", libraryVersionPart, cliStringHashString);
        res = res.replaceAll("[^a-zA-Z0-9_.\\-]", "");
        return res;
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
            String dockerImageTag,
            List<String> entrypoint,
            List<PortBinding> portBindings,
            List<Bind> volumeBindings,
            String containerName) {

        Optional<Container> oldContainer = containerByName(containerName);
        if (oldContainer.isPresent()) {
            dockerClient.removeContainerCmd(oldContainer.get().getId()).withForce(true).exec();
            LOGGER.debug("Old Container Removed");
        }

        HostConfig hostConfig =
                HostConfig.newHostConfig()
                        .withPortBindings(portBindings)
                        .withDns(new ArrayList<>())
                        .withDnsOptions(new ArrayList<>())
                        .withDnsSearch(new ArrayList<>())
                        .withBlkioWeightDevice(new ArrayList<>())
                        .withDevices(new ArrayList<>())
                        .withExtraHosts("host.docker.internal:host-gateway")
                        .withBinds(volumeBindings);

        List<ExposedPort> exposedPorts = new LinkedList<>();
        for (PortBinding portBinding : portBindings) {
            exposedPorts.add(portBinding.getExposedPort());
        }

        CreateContainerResponse createContainerCmd =
                dockerClient
                        .createContainerCmd(dockerImageTag)
                        .withName(containerName)
                        // Some of these options lead to (very undetectable and annoying) errors if
                        // they aren't set.
                        .withAttachStdout(true)
                        .withAttachStdin(true)
                        .withAttachStderr(true)
                        .withTty(true)
                        .withStdinOpen(true)
                        .withStdInOnce(true)
                        .withHostConfig(hostConfig)
                        .withExposedPorts(exposedPorts)
                        .withEntrypoint(entrypoint)
                        .exec();

        return createContainerCmd.getId();
    }

    public boolean buildFailedForTag(String dockerTag) {
        String dockerNameWithTag = this.getBuildImageNameAndTag(dockerTag);
        return this.failedBuildDockerTags.contains(dockerNameWithTag);
    }

    /**
     * Gets the dockerClient this factory has uses (created automatically in init).
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
