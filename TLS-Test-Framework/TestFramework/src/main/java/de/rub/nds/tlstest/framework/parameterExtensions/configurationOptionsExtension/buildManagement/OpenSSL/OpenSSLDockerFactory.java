/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.OpenSSL;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.BuildImageResultCallback;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ResultsCollector.OpenSSLConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerClientTestContainer;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerFactory;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerServerTestContainer;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerTestContainer;
import de.rub.nds.tlstest.framework.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Path;
import java.util.*;

/**
 * This class provides various helper functions that are used to build OpenSSL docker images
 * and manage containers.
 */
public class OpenSSLDockerFactory extends DockerFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private String FACTORY_REPRO_NAME;
    private String TEMP_CONTAINER_NAME;
    private String TEMP_REPRO_NAME;


    // Required by the docker library
    private Volume targetVolumeCcache = new Volume("/src/ccache/");
    private Volume targetVolumeCoverage = new Volume("/covVolume/");
    private Volume targetVolumeCert = new Volume("/cert/");

    private final String volumeNameCcache = "ccache";
    private final String volumeNameCoverage = "coverage";
    private final String volumeNameCert = "cert-data";

    private boolean withCoverage;
    private final String COVERAGE_DIRECTORY_NAME;

    public OpenSSLDockerFactory(DockerClient dockerClient, boolean withCoverage){
        super(dockerClient, "openssl_img");
        this.withCoverage = withCoverage;

        String coverageSuffix = "";
        if(withCoverage){
            coverageSuffix = "-cov";
        }

        FACTORY_REPRO_NAME = "openssl-factory"+coverageSuffix;
        TEMP_CONTAINER_NAME = "temp-openssl-container"+coverageSuffix;
        TEMP_REPRO_NAME = "temp_openssl_img"+coverageSuffix;
        BUILD_REPRO_NAME = "openssl_img"+coverageSuffix;
        CONTAINER_NAME_PREFIX = "container"+coverageSuffix;

        COVERAGE_DIRECTORY_NAME = "CoverageReport_" + Utils.DateToISO8601UTC(new Date());
    }



    public String getFactoryImageNameAndTag(String openSSLBranchName){
        return String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
    }

    public synchronized void buildOpenSSLImageWithFactory(List<String> cliOptions, String dockerTag, Path dockerfileMinPath, String openSSLBranchName, OpenSSLConfigOptionsResultsCollector resultsCollector)  {
        LOGGER.debug(String.format("Build with option string: '%s'", cliOptions));

        // Create the docker factory image for the respective OpenSSL version, if it does not exist so far
        String factoryImageTag = String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);

        // Remove old containers (Only needs to be done if something went wrong)
        Optional<Container> oldTempContainer = containerByName(TEMP_CONTAINER_NAME);
        if(oldTempContainer.isPresent()){
            dockerClient.removeContainerCmd(oldTempContainer.get().getId()).exec();
            LOGGER.debug("Old Container Removed");
        }

        // Create a temporary container to build OpenSSL using ccache
        CreateContainerResponse tempContainer = dockerClient.createContainerCmd(factoryImageTag)
                .withName(TEMP_CONTAINER_NAME)
                .withHostConfig(HostConfig.newHostConfig().withBinds(new Bind(volumeNameCcache, targetVolumeCcache)))
                .withCmd(cliOptions)
                .exec();

        LOGGER.debug("Factory Container created.");

        // Start the created container
        dockerClient.startContainerCmd(tempContainer.getId()).exec();
        InspectContainerResponse containerResp
                = dockerClient.inspectContainerCmd(tempContainer.getId()).exec();

        if(resultsCollector != null){
            resultsCollector.logBuildContainer(new DockerTestContainer(dockerClient, dockerTag, containerResp.getId()));
        }

        LOGGER.debug("Factory Container started.");

        // Wait for the build process to finish and the container stops
        while(containerResp.getState().getRunning()){
            try {
                Thread.sleep(1000);
                containerResp = dockerClient.inspectContainerCmd(tempContainer.getId()).exec();
            }
            catch(InterruptedException e){
                e.printStackTrace();
            }
        }

        LOGGER.debug("\nFactory Container finished.");

        // Commit the build to create a final image
        String tempImageId = dockerClient.commitCmd(tempContainer.getId())
                .withRepository(TEMP_REPRO_NAME)
                .withTag(dockerTag)
                .exec();

        String buildArg = String.format("%s:%s", TEMP_REPRO_NAME, dockerTag);
        String finalImageTag = getOpenSSLBuildImageNameAndTag(dockerTag);
        dockerClient.buildImageCmd()
                .withDockerfile(dockerfileMinPath.toFile())
                .withTags(new HashSet<>(Arrays.asList(finalImageTag)))
                .withBuildArg("TEMP_REPRO", buildArg).exec(new BuildImageResultCallback()).awaitImageId();

        LOGGER.debug("Final Image built");

        // Remove the temporary image and container
        dockerClient.removeImageCmd(tempImageId).exec();
        dockerClient.removeContainerCmd(tempContainer.getId()).exec();
    }

    public DockerServerTestContainer createDockerServer(String dockerTag,
                                                        String dockerHost,
                                                        Integer dockerTlsPort,
                                                        Integer managerPort)
    {
        final Integer CONTAINER_PORT_TLS_SERVER = 4433;
        final Integer CONTAINER_MANAGER_PORT = 8090;
        List<String> entrypoint;
        if(withCoverage){
            final String coverageOutDir = String.format("%s/%s", COVERAGE_DIRECTORY_NAME, dockerTag);
            entrypoint = Arrays.asList("/usr/opensslEntrypoint.sh", "-d", coverageOutDir, "server");
        }
        else{
            entrypoint = Arrays.asList("server-entrypoint", "openssl", "s_server","-accept", CONTAINER_PORT_TLS_SERVER.toString(), "-key", "/cert/ec256key.pem", "-cert", "/cert/ec256cert.pem");
        }
        List<PortBinding> portBindings = new LinkedList<>();
        List<Bind> volumeBindings = new LinkedList<>();

        ExposedPort exposedTlsServerPort = ExposedPort.tcp(CONTAINER_PORT_TLS_SERVER);
        portBindings.add(new PortBinding(Ports.Binding.bindIpAndPort(dockerHost, dockerTlsPort), exposedTlsServerPort));

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(new PortBinding(Ports.Binding.bindIpAndPort(dockerHost, managerPort), exposedManagerPort));

        volumeBindings.add(new Bind(volumeNameCert, targetVolumeCert, AccessMode.ro, SELContext.DEFAULT, true));
        if(withCoverage){
            volumeBindings.add(new Bind(volumeNameCoverage, targetVolumeCoverage));
        }

        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId = createDockerContainer(getOpenSSLBuildImageNameAndTag(dockerTag), entrypoint, portBindings, volumeBindings, containerName);
        DockerServerTestContainer containerInfo = new DockerServerTestContainer(dockerClient, dockerTag, dockerContainerId, dockerHost, dockerTlsPort, managerPort);

        return containerInfo;
    }

    public DockerClientTestContainer createDockerClient(String dockerTag,
                                                        String dockerManagerHost,
                                                        Integer dockeManagerPort,
                                                        String tlsServerHost,
                                                        Integer tlsServerPort)
    {
        final Integer CONTAINER_PORT_MANAGER = 8090;

        String connectionDest = String.format("%s:%d", tlsServerHost, tlsServerPort);
        List<String> entrypoint;
        if(withCoverage){
            final String coverageOutDir = String.format("%s/%s", COVERAGE_DIRECTORY_NAME, dockerTag);
            entrypoint = Arrays.asList("/usr/opensslEntrypoint.sh", "-d", coverageOutDir, "client", connectionDest);
        }
        else{
            entrypoint = Arrays.asList("client-entrypoint", "openssl", "s_client", "-connect", connectionDest/*, "-bind", CONTAINER_PORT_TLS_CLIENT.toString()*/);
        }

        List<PortBinding> portBindings = new LinkedList<>();
        List<Bind> volumeBindings = new LinkedList<>();

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_PORT_MANAGER);
        portBindings.add(new PortBinding(Ports.Binding.bindIpAndPort(dockerManagerHost, dockeManagerPort), exposedManagerPort));

        if(withCoverage){
            volumeBindings.add(new Bind(volumeNameCoverage, targetVolumeCoverage));
        }

        String containerName = String.format("%s_client_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId = createDockerContainer(getOpenSSLBuildImageNameAndTag(dockerTag), entrypoint, portBindings, volumeBindings, containerName);

        DockerClientTestContainer containerInfo = new DockerClientTestContainer(dockerClient, dockerTag, dockerContainerId,
                dockerManagerHost, dockeManagerPort, tlsServerPort);

        return containerInfo;
    }


    public String createFactoryImage(Path dockerfileFactoryPath, String openSSLBranchName){
        // Create the docker factory image for the respective OpenSSL version, if it does not exist so far
        String factoryImageTag = String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
        LOGGER.debug("Build factory image.");
        dockerClient.buildImageCmd()
                .withDockerfile(dockerfileFactoryPath.toFile())
                .withTags(new HashSet<>(Arrays.asList(factoryImageTag)))
                .withBuildArg("OPENSSL_BRANCH", openSSLBranchName).exec(new BuildImageResultCallback()).awaitImageId();

        return factoryImageTag;
    }


}
