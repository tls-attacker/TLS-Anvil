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
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.DockerContainerLogFile;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeoutException;

/**
 * DockerFactory to build OpenSSL server and client containers using a two-step build procedure to utilize ccache.
 * Utilizes the files in '[TLS-Docker-Library path]/images/openssl/configurationOptionsFactoryWithCoverage/'
 */
public class OpenSSLDockerFactory extends DockerFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String FACTORY_REPRO_NAME;
    private final String TEMP_CONTAINER_NAME;
    private final String TEMP_REPRO_NAME;


    // Required by the docker library
    private final Volume targetVolumeCcache = new Volume("/src/ccache/");
    private final Volume targetVolumeCoverage = new Volume("/covVolume/");
    private final Volume targetVolumeCert = new Volume("/cert/");

    private final String volumeNameCoverage = "coverage";

    private final boolean withCoverage;
    private final String COVERAGE_DIRECTORY_NAME;

    private final String CCACHE_VOLUME_NAME = "ccache-cache";

    private Path dockerfileMinPath;

    public OpenSSLDockerFactory(ConfigurationOptionsConfig configurationOptionsConfig){
        super(configurationOptionsConfig, "openssl_img");
        this.withCoverage = configurationOptionsConfig.isWithCoverage();

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

    @Override
    public void init(){
        super.init();

        // Create a ccache volume if it does not exist so far
        if(dockerClient.listVolumesCmd().exec().getVolumes().stream().noneMatch(response -> response.getName().equals(CCACHE_VOLUME_NAME))){
            // If a volume with the specified name exists:
            dockerClient.createVolumeCmd().withName(CCACHE_VOLUME_NAME).exec();
        }

        Path dockerLibraryPath = configOptionsConfig.getDockerLibraryPath();
        String subfolderName;
        if(configOptionsConfig.isWithCoverage()){
            subfolderName = "configurationOptionsFactoryWithCoverage";
        }
        else{
            subfolderName = "configurationOptionsFactory";
        }

        Path partialPathToFactoryDockerfile = Paths.get("images", "openssl", subfolderName, "Dockerfile_Factory_OpenSSL");
        Path pathToFactoryDockerfile = dockerLibraryPath.resolve(partialPathToFactoryDockerfile);

        Path partialPathToMinDockerfile = Paths.get("images", "openssl", subfolderName, "Dockerfile_Min_OpenSSL");
        Path pathToMinDockerfile = dockerLibraryPath.resolve(partialPathToMinDockerfile);

        if(!Files.exists(pathToMinDockerfile)){
            throw new RuntimeException(
                    String.format("Dockerfile '%s' does not exist. Have you configured the right Docker Library path? " +
                            "Or are you using an old DockerLibrary Version?", pathToMinDockerfile));
        }


        if(!Files.exists(pathToFactoryDockerfile)){
            throw new RuntimeException(
                    String.format("Dockerfile '%s' does not exist. Have you configured the right Docker Library path? " +
                            "Or are you using an old DockerLibrary Version?", pathToFactoryDockerfile));
        }



        // Build the factory if it does not exist
        // Note that the library name must be a branch in OpenSSL's github.
        String openSSLBranchName = configOptionsConfig.getTlsVersionName();
        String factoryImageNameWithTag = getFactoryImageNameAndTag(openSSLBranchName);
        if(!dockerNameWithTagExists(factoryImageNameWithTag)){
            LOGGER.info("Create OpenSSL factory docker image...");
            createFactoryImage(pathToFactoryDockerfile, openSSLBranchName);
        }

        dockerfileMinPath = pathToMinDockerfile;


    }


    public String getFactoryImageNameAndTag(String openSSLBranchName){
        return String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
    }

    @Override
    protected synchronized boolean buildDockerImage(List<String> cliOptions, String dockerTag, String openSSLBranchName, ConfigOptionsResultsCollector resultsCollector)  {
        if(resultsCollector == null){
            throw new NullPointerException("resultsCollector is null.");
        }


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
        String volumeNameCcache = "ccache";
        CreateContainerResponse tempContainer = dockerClient.createContainerCmd(factoryImageTag)
                .withName(TEMP_CONTAINER_NAME)
                .withHostConfig(HostConfig.newHostConfig().withBinds(new Bind(volumeNameCcache, targetVolumeCcache)))
                .withCmd(cliOptions)
                .exec();

        DockerContainer factoryContainer = new DockerContainer(factoryImageTag, tempContainer.getId(), dockerClient);

        LOGGER.debug("Factory Container created.");

        // Start the created container
        factoryContainer.start();
        DockerContainerLogFile logFile = factoryContainer.enableContainerLogging(resultsCollector, "BuildLog", dockerTag);


        LOGGER.debug("Factory Container started.");
        final int timeoutMs = 1800000; // 30 min
        try {
            factoryContainer.waitForState(DockerContainerState.NOT_RUNNING, timeoutMs); // Building timeout 30 min
        } catch (TimeoutException e) {
            factoryContainer.remove();
            LOGGER.error("Timeout while building OpenSSL docker image. (tag: '{}', configured with: '{}', timeout after {} min)", dockerTag, cliOptions, timeoutMs/60000);
            return false;
        }

        InspectContainerResponse containerResp = dockerClient.inspectContainerCmd(factoryContainer.getContainerId()).exec();

        if(containerResp.getState().getExitCodeLong() == null || containerResp.getState().getExitCodeLong() > 0) {
            LOGGER.error("Cannot build OpenSSL docker image. (tag: '{}', configured with: '{}')", dockerTag, cliOptions);
            if(logFile != null){
                LOGGER.error("See docker build log ({}) for more information.", logFile.getLogFile().getAbsolutePath());
            }
            dockerClient.removeContainerCmd(tempContainer.getId()).exec();
            return false;
        }


        LOGGER.debug("\nFactory Container finished.");

        // Commit the build to create a final image
        String tempImageId = dockerClient.commitCmd(tempContainer.getId())
                .withRepository(TEMP_REPRO_NAME)
                .withTag(dockerTag)
                .exec();

        String buildArg = String.format("%s:%s", TEMP_REPRO_NAME, dockerTag);
        String finalImageTag = getBuildImageNameAndTag(dockerTag);
        dockerClient.buildImageCmd()
                .withDockerfile(dockerfileMinPath.toFile())
                .withTags(new HashSet<>(Collections.singletonList(finalImageTag)))
                .withBuildArg("TEMP_REPRO", buildArg).exec(new BuildImageResultCallback()).awaitImageId();

        LOGGER.debug("Final Image built");

        // Remove the temporary image and container
        dockerClient.removeImageCmd(tempImageId).exec();
        factoryContainer.remove();
        //dockerClient.removeContainerCmd(tempContainer.getId()).exec();
        return true;
    }

    public DockerServerTestContainer createDockerServer(String dockerTag,
                                                        String dockerHost,
                                                        Integer dockerManagerPort, Integer dockerTlsPort)
    {
        final int CONTAINER_PORT_TLS_SERVER = 4433;
        final int CONTAINER_MANAGER_PORT = 8090;
        List<String> entrypoint;
        if(withCoverage){
            final String coverageOutDir = String.format("%s/%s", COVERAGE_DIRECTORY_NAME, dockerTag);
            entrypoint = Arrays.asList("/usr/opensslEntrypoint.sh", "-d", coverageOutDir, "server");
        }
        else{
            entrypoint = Arrays.asList("server-entrypoint", "openssl", "s_server","-accept", Integer.toString(CONTAINER_PORT_TLS_SERVER), "-key", "/cert/ec256key.pem", "-cert", "/cert/ec256cert.pem", "-comp");
        }
        List<PortBinding> portBindings = new LinkedList<>();
        List<Bind> volumeBindings = new LinkedList<>();

        ExposedPort exposedTlsServerPort = ExposedPort.tcp(CONTAINER_PORT_TLS_SERVER);
        portBindings.add(new PortBinding(Ports.Binding.bindIpAndPort(dockerHost, dockerTlsPort), exposedTlsServerPort));

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(new PortBinding(Ports.Binding.bindIpAndPort(dockerHost, dockerManagerPort), exposedManagerPort));

        String volumeNameCert = "cert-data";
        volumeBindings.add(new Bind(volumeNameCert, targetVolumeCert, AccessMode.ro, SELContext.DEFAULT, true));
        if(withCoverage){
            volumeBindings.add(new Bind(volumeNameCoverage, targetVolumeCoverage));
        }

        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId = createDockerContainer(getBuildImageNameAndTag(dockerTag), entrypoint, portBindings, volumeBindings, containerName);

        return new DockerServerTestContainer(dockerClient, dockerTag, dockerContainerId, dockerHost, dockerManagerPort, dockerTlsPort);
    }

    public DockerClientTestContainer createDockerClient(String dockerTag,
                                                        String dockerManagerHost,
                                                        Integer dockerManagerPort,
                                                        String tlsServerHost,
                                                        Integer tlsServerPort)
    {
        final int CONTAINER_PORT_MANAGER = 8090;

        String connectionDest = String.format("%s:%d", tlsServerHost, tlsServerPort);
        List<String> entrypoint;
        if(withCoverage){
            final String coverageOutDir = String.format("%s/%s", COVERAGE_DIRECTORY_NAME, dockerTag);
            entrypoint = Arrays.asList("/usr/opensslEntrypoint.sh", "-d", coverageOutDir, "client", connectionDest);
        }
        else{
            entrypoint = Arrays.asList("client-entrypoint", "openssl", "s_client", "-connect", connectionDest, "-comp");
        }

        List<PortBinding> portBindings = new LinkedList<>();
        List<Bind> volumeBindings = new LinkedList<>();

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_PORT_MANAGER);
        portBindings.add(new PortBinding(Ports.Binding.bindIpAndPort(dockerManagerHost, dockerManagerPort), exposedManagerPort));

        if(withCoverage){
            volumeBindings.add(new Bind(volumeNameCoverage, targetVolumeCoverage));
        }

        String containerName = String.format("%s_client_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId = createDockerContainer(getBuildImageNameAndTag(dockerTag), entrypoint, portBindings, volumeBindings, containerName);

        return new DockerClientTestContainer(dockerClient, dockerTag, dockerContainerId,
                dockerManagerHost, dockerManagerPort, configOptionsConfig.getDockerClientDestinationHostName(), tlsServerPort);
    }


    public String createFactoryImage(Path dockerfileFactoryPath, String openSSLBranchName){
        // Create the docker factory image for the respective OpenSSL version, if it does not exist so far
        String factoryImageTag = String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
        LOGGER.debug("Build factory image.");
        dockerClient.buildImageCmd()
                .withDockerfile(dockerfileFactoryPath.toFile())
                .withTags(new HashSet<>(Collections.singletonList(factoryImageTag)))
                .withBuildArg("OPENSSL_BRANCH", openSSLBranchName).exec(new BuildImageResultCallback()).awaitImageId();

        return factoryImageTag;
    }


}
