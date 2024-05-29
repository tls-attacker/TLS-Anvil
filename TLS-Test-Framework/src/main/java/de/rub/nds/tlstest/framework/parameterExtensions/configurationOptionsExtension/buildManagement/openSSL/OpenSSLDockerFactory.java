/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.openSSL;

import com.github.dockerjava.api.command.BuildImageResultCallback;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsMetadataResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.DockerContainerLogFile;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.utils.Utils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * DockerFactory to build OpenSSL server and client containers using a two-step build procedure to
 * utilize ccache. Utilizes the files in '[TLS-Docker-Library
 * path]/images/openssl/configurationOptionsFactoryWithCoverage/'
 */
public class OpenSSLDockerFactory extends DockerFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String factoryRepoName;
    private final String tempContainerPrefix;
    private final String tempRepoName;

    // Required by the docker library
    private final Volume targetVolumeCcache = new Volume("/src/ccache/");
    private final Volume targetVolumeCoverage = new Volume("/covVolume/");
    private final Volume targetVolumeCert = new Volume("/cert/");

    private final String volumeNameCoverage = "coverage";

    private final String coverageDirectoryName;

    private static final String CCACHE_VOLUME_NAME = "ccache-cache";

    private Path dockerfileMinPath;

    private static final int DEFAULT_BUILD_TIMEOUT = 1800000;
    private static final int CONTAINER_PORT_TLS_SERVER = 4433;
    private static final int CONTAINER_MANAGER_PORT = 8090;

    public OpenSSLDockerFactory(ConfigurationOptionsConfig configurationOptionsConfig) {
        super(configurationOptionsConfig, "openssl_img");

        String coverageSuffix = "-cov";

        factoryRepoName = "openssl-factory" + coverageSuffix;
        tempContainerPrefix = "temp-openssl-container" + coverageSuffix;
        tempRepoName = "temp_openssl_img" + coverageSuffix;
        BUILD_REPRO_NAME = "openssl_img" + coverageSuffix;
        CONTAINER_NAME_PREFIX = "container" + coverageSuffix;

        coverageDirectoryName = "CoverageReport_" + Utils.DateToISO8601UTC(new Date());
    }

    @Override
    public void init() {
        super.init();

        // Create a ccache volume if it does not exist so far
        if (dockerClient.listVolumesCmd().exec().getVolumes().stream()
                .noneMatch(response -> response.getName().equals(CCACHE_VOLUME_NAME))) {
            // If a volume with the specified name exists:
            dockerClient.createVolumeCmd().withName(CCACHE_VOLUME_NAME).exec();
        }

        Path dockerLibraryPath = configOptionsConfig.getDockerLibraryPath();
        String subfolderName;
        subfolderName = "configurationOptionsFactoryWithCoverage";

        Path partialPathToFactoryDockerfile =
                Paths.get("images", "openssl", subfolderName, "Dockerfile_Factory_OpenSSL");
        Path pathToFactoryDockerfile = dockerLibraryPath.resolve(partialPathToFactoryDockerfile);

        Path partialPathToMinDockerfile =
                Paths.get("images", "openssl", subfolderName, "Dockerfile_Min_OpenSSL");
        Path pathToMinDockerfile = dockerLibraryPath.resolve(partialPathToMinDockerfile);

        if (!Files.exists(pathToMinDockerfile)) {
            throw new RuntimeException(
                    String.format(
                            "Dockerfile '%s' does not exist. Have you configured the right Docker Library path? "
                                    + "Or are you using an old DockerLibrary Version?",
                            pathToMinDockerfile));
        }

        if (!Files.exists(pathToFactoryDockerfile)) {
            throw new RuntimeException(
                    String.format(
                            "Dockerfile '%s' does not exist. Have you configured the right Docker Library path? "
                                    + "Or are you using an old DockerLibrary Version?",
                            pathToFactoryDockerfile));
        }

        // Build the factory if it does not exist
        // Note that the library name must be a branch in OpenSSL's github.
        String openSSLBranchName = configOptionsConfig.getTlsVersionName();
        String factoryImageNameWithTag = getFactoryImageNameAndTag(openSSLBranchName);
        if (!dockerNameWithTagExists(factoryImageNameWithTag)) {
            LOGGER.info("Create OpenSSL factory docker image...");
            createFactoryImage(pathToFactoryDockerfile, openSSLBranchName);
        }

        dockerfileMinPath = pathToMinDockerfile;
    }

    public String getFactoryImageNameAndTag(String openSSLBranchName) {
        return String.format("%s:%s", factoryRepoName, openSSLBranchName);
    }

    @Override
    protected boolean buildDockerImage(
            List<String> cliOptions,
            String dockerTag,
            String openSSLBranchName,
            ConfigOptionsMetadataResultsCollector resultsCollector) {
        DockerContainer factoryContainer;
        CreateContainerResponse tempContainer;
        String tempContainerName = String.format("%s_%s", tempContainerPrefix, dockerTag);
        synchronized (this) {
            if (resultsCollector == null) {
                throw new NullPointerException("resultsCollector is null.");
            }

            LOGGER.debug(String.format("Build with option string: '%s'", cliOptions));

            // Create the docker factory image for the respective OpenSSL version, if it does not
            // exist so far
            String factoryImageTag = String.format("%s:%s", factoryRepoName, openSSLBranchName);

            // Remove old containers (Only needs to be done if something went wrong) TODO
            Optional<Container> oldTempContainer = containerByName(tempContainerName);
            if (oldTempContainer.isPresent()) {
                dockerClient.removeContainerCmd(oldTempContainer.get().getId()).exec();
                LOGGER.debug("Old Container with name '{}' removed.", tempContainerName);
            }

            // Create a temporary container to build OpenSSL using ccache
            tempContainer =
                    dockerClient
                            .createContainerCmd(factoryImageTag)
                            .withName(tempContainerName)
                            .withHostConfig(
                                    HostConfig.newHostConfig()
                                            .withBinds(
                                                    new Bind(
                                                            CCACHE_VOLUME_NAME,
                                                            targetVolumeCcache)))
                            .withCmd(cliOptions)
                            .exec();

            factoryContainer =
                    new DockerContainer(factoryImageTag, tempContainer.getId(), dockerClient);

            LOGGER.debug("Factory Container created.");
        }

        // Start the created container
        factoryContainer.start();
        DockerContainerLogFile logFile =
                factoryContainer.enableContainerLogging(resultsCollector, "BuildLog", dockerTag);

        LOGGER.debug("Factory Container started.");
        final int timeoutMs = DEFAULT_BUILD_TIMEOUT;
        try {
            factoryContainer.waitForState(DockerContainerState.NOT_RUNNING, timeoutMs);
        } catch (TimeoutException e) {
            factoryContainer.remove();
            LOGGER.error(
                    "Timeout while building OpenSSL docker image. (tag: '{}', configured with: '{}', timeout after {} min)",
                    dockerTag,
                    cliOptions,
                    timeoutMs / 60000);
            return false;
        }
        synchronized (this) {
            InspectContainerResponse containerResp =
                    dockerClient.inspectContainerCmd(factoryContainer.getContainerId()).exec();

            if (containerResp.getState().getExitCodeLong() == null
                    || containerResp.getState().getExitCodeLong() > 0) {
                LOGGER.error(
                        "Cannot build OpenSSL docker image. (tag: '{}', configured with: '{}')",
                        dockerTag,
                        cliOptions);
                if (logFile != null) {
                    LOGGER.error(
                            "See docker build log ({}) for more information.",
                            logFile.getLogFile().getAbsolutePath());
                }
                dockerClient.removeContainerCmd(tempContainer.getId()).exec();
                return false;
            }

            LOGGER.debug("\nFactory Container finished.");

            // Commit the build to create a final image
            String tempImageId =
                    dockerClient
                            .commitCmd(tempContainer.getId())
                            .withRepository(tempRepoName)
                            .withTag(dockerTag)
                            .exec();

            String buildArg = String.format("%s:%s", tempRepoName, dockerTag);
            String finalImageTag = getBuildImageNameAndTag(dockerTag);
            dockerClient
                    .buildImageCmd()
                    .withDockerfile(dockerfileMinPath.toFile())
                    .withTags(new HashSet<>(Collections.singletonList(finalImageTag)))
                    .withBuildArg("TEMP_REPRO", buildArg)
                    .exec(new BuildImageResultCallback())
                    .awaitImageId();

            LOGGER.debug("Final Image built");

            // Remove the temporary image and container
            dockerClient.removeImageCmd(tempImageId).exec();
            factoryContainer.remove();
            return true;
        }
    }

    public DockerServerTestContainer createDockerServer(
            String dockerTag, String dockerHost, Integer dockerManagerPort, Integer dockerTlsPort) {
        List<String> entrypoint;

        final String coverageOutDir = String.format("%s/%s", coverageDirectoryName, dockerTag);
        entrypoint = Arrays.asList("/usr/opensslEntrypoint.sh", "-d", coverageOutDir, "server");

        List<PortBinding> portBindings = new LinkedList<>();
        List<Bind> volumeBindings = new LinkedList<>();

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

        String volumeNameCert = "cert-data";
        volumeBindings.add(
                new Bind(
                        volumeNameCert, targetVolumeCert, AccessMode.ro, SELContext.DEFAULT, true));
        volumeBindings.add(new Bind(volumeNameCoverage, targetVolumeCoverage));

        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId =
                createDockerContainer(
                        getBuildImageNameAndTag(dockerTag),
                        entrypoint,
                        portBindings,
                        volumeBindings,
                        containerName);

        return new DockerServerTestContainer(
                dockerClient,
                dockerTag,
                dockerContainerId,
                dockerHost,
                dockerManagerPort,
                dockerTlsPort);
    }

    public DockerClientTestContainer createDockerClient(
            String dockerTag,
            String dockerManagerHost,
            Integer dockerManagerPort,
            String tlsServerHost,
            Integer tlsServerPort) {

        String connectionDest = String.format("%s:%d", tlsServerHost, tlsServerPort);
        List<String> entrypoint;

        final String coverageOutDir = String.format("%s/%s", coverageDirectoryName, dockerTag);
        entrypoint =
                Arrays.asList(
                        "/usr/opensslEntrypoint.sh",
                        "-d",
                        coverageOutDir,
                        "client",
                        connectionDest);

        List<PortBinding> portBindings = new LinkedList<>();
        List<Bind> volumeBindings = new LinkedList<>();

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerManagerPort),
                        exposedManagerPort));
        volumeBindings.add(new Bind(volumeNameCoverage, targetVolumeCoverage));

        String containerName = String.format("%s_client_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId =
                createDockerContainer(
                        getBuildImageNameAndTag(dockerTag),
                        entrypoint,
                        portBindings,
                        volumeBindings,
                        containerName);

        return new DockerClientTestContainer(
                dockerClient,
                dockerTag,
                dockerContainerId,
                dockerManagerHost,
                dockerManagerPort,
                configOptionsConfig.getDockerClientDestinationHostName(),
                tlsServerPort);
    }

    public synchronized String createFactoryImage(
            Path dockerfileFactoryPath, String openSSLBranchName) {
        // Create the docker factory image for the respective OpenSSL version, if it does not exist
        // so far
        String factoryImageTag = String.format("%s:%s", factoryRepoName, openSSLBranchName);
        LOGGER.debug("Build factory image.");
        dockerClient
                .buildImageCmd()
                .withDockerfile(dockerfileFactoryPath.toFile())
                .withTags(new HashSet<>(Collections.singletonList(factoryImageTag)))
                .withBuildArg("OPENSSL_BRANCH", openSSLBranchName)
                .exec(new BuildImageResultCallback())
                .awaitImageId();

        return factoryImageTag;
    }
}
