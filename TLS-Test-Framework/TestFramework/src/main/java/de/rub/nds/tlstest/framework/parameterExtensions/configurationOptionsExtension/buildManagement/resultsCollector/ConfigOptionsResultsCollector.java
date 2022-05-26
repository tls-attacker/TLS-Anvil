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

/**
 * This class is used to collect additional data (and metadata) about the test execution of config option tests and the
 * build procedure of the different required docker images.
 */
public class ConfigOptionsResultsCollector {

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
     * @param directory - defines the directory the results should be stored in (new directory is created within)
     * @param config - the configuration options config used
     * @param dockerClient - the docker client
     */
    public ConfigOptionsResultsCollector(Path directory, ConfigurationOptionsConfig config, DockerClient dockerClient){
        containerIdToLogger = new HashMap<>();
        this.dockerClient = dockerClient;

        directory = directory.toAbsolutePath();

        folderDirectoryPath = directory.resolve(RESULTS_FOLDER_NAME);
        prepareDirectory(folderDirectoryPath);

        containerLogDirectoryPath = folderDirectoryPath.resolve(CONTAINER_LOG_FOLDER_NAME);
        prepareDirectory(containerLogDirectoryPath);

        buildContainerLogDirectoryPath = folderDirectoryPath.resolve(BUILD_CONTAINER_LOG_FOLDER_NAME);
        prepareDirectory(buildContainerLogDirectoryPath);

        buildOverviewLogFile = new BuildOverviewLogFile(folderDirectoryPath, "buildsOverview.csv", config);
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
    public synchronized void logNewBuildCreated(Set<ConfigurationOptionDerivationParameter> optionSet, String dockerTag, long buildTime)
    {
        buildOverviewLogFile.logBuild(optionSet, dockerTag, buildTime);
    }

    /**
     * Logs that a tls library was accessed. Evaluation is done in the end.
     *
     * @param optionSet - The option set of the accessed implementation
     * @param dockerTag - The docker image tag of the accessed implementation
     */
    public synchronized void logBuildAccess(Set<ConfigurationOptionDerivationParameter> optionSet, String dockerTag){
        buildAccessLogFile.increaseAccessCounter(dockerTag);
        buildOverviewLogFile.logBuild(optionSet, dockerTag, -1);
    }

    /**
     * Finalized all results that are only evaluated in the end (e.g. the total build access count)
     */
    public synchronized void finalizeResults(){
        buildAccessLogFile.finalizeResults();
    }

    /**
     * Log a container that is used for building tls library (is stored in another directory than logContainer).
     *
     * @param container - The container to log
     */
    public synchronized void logBuildContainer(DockerContainer container){
        logDockerContainer(container, buildContainerLogDirectoryPath);
    }

    /**
     * Log a container.
     *
     * @param container - The container to log
     */
    public synchronized void logContainer(DockerContainer container){
        logDockerContainer(container, containerLogDirectoryPath);
    }


    private synchronized void logDockerContainer(DockerContainer container, Path path) {
        String containerId = container.getContainerId();
        if(containerIdToLogger.containsKey(containerId)){
            // Logger does already exist
            return;
        }
        DockerContainerLogFile containerLogger = new DockerContainerLogFile(path, "Log"+container.getDockerTag()+".log", dockerClient);
        containerIdToLogger.put(containerId, containerLogger);
        containerLogger.logDockerContainer(container);
    }

    private void prepareDirectory(Path directoryPath){
        File directory = directoryPath.toFile();

        if(!directory.exists()){
            directory.mkdirs();
        }
    }

}
