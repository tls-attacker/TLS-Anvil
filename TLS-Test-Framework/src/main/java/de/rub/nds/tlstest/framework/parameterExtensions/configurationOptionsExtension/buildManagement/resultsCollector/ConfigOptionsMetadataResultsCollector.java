/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector;

import com.github.dockerjava.api.DockerClient;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerContainer;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import java.io.*;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class is used to collect additional data (and metadata) about the test execution of config
 * option tests and the build procedure of the different required docker images.
 */
public class ConfigOptionsMetadataResultsCollector {

    private static final Logger LOGGER = LogManager.getLogger();

    final String RESULTS_FOLDER_NAME = "ConfigOptionsResults/";
    final String CONTAINER_LOG_FOLDER_NAME = "ContainerLog/";
    final String BUILD_CONTAINER_LOG_FOLDER_NAME = "BuildLog/";

    final Path folderDirectoryPath;
    final Path containerLogDirectoryPath;
    final Path buildContainerLogDirectoryPath;

    DockerClient dockerClient;

    Map<String, DockerContainerLogFile> containerIdToLogger;

    BuildOverviewLogFile buildOverviewLogFile;
    GeneralInfoLogFile generalInfoLogFile;
    BuildAccessLogFile buildAccessLogFile;

    /**
     * Constructor.
     *
     * @param directory - defines the directory the results should be stored in (new directory is
     *     created within)
     * @param config - the configuration options config used
     * @param dockerClient - the docker client
     */
    public ConfigOptionsMetadataResultsCollector(
            Path directory, ConfigurationOptionsConfig config, DockerClient dockerClient) {
        containerIdToLogger = new HashMap<>();
        this.dockerClient = dockerClient;

        directory = directory.toAbsolutePath();

        folderDirectoryPath = directory.resolve(RESULTS_FOLDER_NAME);
        prepareDirectory(folderDirectoryPath);

        containerLogDirectoryPath = folderDirectoryPath.resolve(CONTAINER_LOG_FOLDER_NAME);
        prepareDirectory(containerLogDirectoryPath);

        buildContainerLogDirectoryPath =
                folderDirectoryPath.resolve(BUILD_CONTAINER_LOG_FOLDER_NAME);
        prepareDirectory(buildContainerLogDirectoryPath);

        buildOverviewLogFile =
                new BuildOverviewLogFile(folderDirectoryPath, "buildsOverview.csv", config);
        generalInfoLogFile = new GeneralInfoLogFile(folderDirectoryPath, "generalInfo.csv", config);
        buildAccessLogFile = new BuildAccessLogFile(folderDirectoryPath, "buildAccesses.csv");
    }

    /**
     * Log that a new tls library build was created
     *
     * @param optionSet - the set of options used for building the tls library build
     * @param dockerTag - the docker image tag of the build
     * @param buildTime - the time it took for building the build
     */
    public synchronized void logNewBuildCreated(
            Set<ConfigurationOptionDerivationParameter> optionSet,
            String dockerTag,
            long buildTime,
            boolean success) {
        buildOverviewLogFile.logBuild(optionSet, dockerTag, buildTime, success);
    }

    /**
     * Logs that a tls library was accessed. Evaluation is done in the end.
     *
     * @param optionSet - The option set of the accessed implementation
     * @param dockerTag - The docker image tag of the accessed implementation
     */
    public synchronized void logBuildAccess(
            Set<ConfigurationOptionDerivationParameter> optionSet, String dockerTag) {
        buildAccessLogFile.increaseAccessCounter(dockerTag);
        buildOverviewLogFile.logBuild(optionSet, dockerTag, -1, true);
    }

    /**
     * Finalized all results that are only evaluated in the end (e.g. the total build access count)
     */
    public synchronized void finalizeResults() {
        buildAccessLogFile.finalizeResults();
    }

    /**
     * Log a container.
     *
     * @param container - The container to log
     */
    public synchronized DockerContainerLogFile logContainer(
            DockerContainer container, String category, String name) {
        Path logDirectoryPath = folderDirectoryPath.resolve(category + "/");
        prepareDirectory(logDirectoryPath);
        return logDockerContainer(container, logDirectoryPath, name);
    }

    private synchronized DockerContainerLogFile logDockerContainer(
            DockerContainer container, Path path, String name) {
        String containerId = container.getContainerId();
        if (containerIdToLogger.containsKey(containerId)) {
            // Logger does already exist
            throw new RuntimeException("Cannot log non-existing container!");
        }
        DockerContainerLogFile containerLogger =
                new DockerContainerLogFile(path, "Log_" + name + ".log", container);
        containerIdToLogger.put(containerId, containerLogger);
        return containerLogger;
    }

    private void prepareDirectory(Path directoryPath) {
        File directory = directoryPath.toFile();

        if (!directory.exists()) {
            boolean success = directory.mkdirs();
            if (!success) {
                LOGGER.error("Cannot create directories '{}'", directory);
                throw new RuntimeException("Cannot create directories.");
            }
        }
    }
}
