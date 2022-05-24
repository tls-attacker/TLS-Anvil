/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ResultsCollector;

import com.github.dockerjava.api.DockerClient;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerTestContainer;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;

import java.io.*;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This class is used to collect additional data (and metadata) about the test execution of config option tests and the
 * build procedure of the different required OpenSSL docker images.
 */
public class OpenSSLConfigOptionsResultsCollector {

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

    public OpenSSLConfigOptionsResultsCollector(Path directory, ConfigurationOptionsConfig config, DockerClient dockerClient){
        containerIdToLogger = new HashMap<>();
        this.dockerClient = dockerClient;

        directory = directory.toAbsolutePath();
        /*if(!Files.exists(directory)){
            throw new RuntimeException(String.format("Directory '%s' does not exist.", directory.toAbsolutePath()));
        }*/
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

    public synchronized void logNewOpenSSLBuildCreated(Set<ConfigurationOptionDerivationParameter> optionSet, String dockerTag, long buildTime)
    {
        buildOverviewLogFile.logBuild(optionSet, dockerTag, buildTime);
    }

    public synchronized void logBuildAccess(Set<ConfigurationOptionDerivationParameter> optionSet, String dockerTag){
        buildAccessLogFile.increaseAccessCounter(dockerTag);
        buildOverviewLogFile.logBuild(optionSet, dockerTag, -1);
    }

    public synchronized void finalizeResults(){
        buildAccessLogFile.finalizeResults();
    }

    public synchronized void logBuildContainer(DockerTestContainer container){
        logDockerContainer(container, buildContainerLogDirectoryPath);
    }

    public synchronized void logOpenSSLContainer(DockerTestContainer container){
        logDockerContainer(container, containerLogDirectoryPath);
    }

    private synchronized void logDockerContainer(DockerTestContainer container, Path path) {
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
        /*else{
            for(File file: directory.listFiles()) {
                if (!file.isDirectory()) {
                    file.delete();
                }
            }
        }*/
    }

}
