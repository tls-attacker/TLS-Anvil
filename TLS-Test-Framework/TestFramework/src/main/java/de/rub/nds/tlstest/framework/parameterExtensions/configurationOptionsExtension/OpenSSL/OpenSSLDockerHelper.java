/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.BuildImageResultCallback;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector.OpenSSLConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Predicate;

/**
 * This class provides various helper functions that are used to build OpenSSL docker images
 * and manage containers.
 */
public class OpenSSLDockerHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private String FACTORY_REPRO_NAME;
    private String TEMP_CONTAINER_NAME;
    private String TEMP_REPRO_NAME;
    private String BUILD_REPRO_NAME;
    private String CONTAINER_NAME_PREFIX;

    // Required by the docker library
    private Volume targetVolumeCcache = new Volume("/src/ccache/");
    private Volume targetVolumeCoverage = new Volume("/covVolume/");
    private Volume targetVolumeCert = new Volume("/cert/");

    private final String volumeNameCcache = "ccache";
    private final String volumeNameCoverage = "coverage";
    private final String volumeNameCert = "cert-data";

    private DockerClient dockerClient;

    private boolean withCoverage;
    private final String COVERAGE_DIRECTORY_NAME;

    public OpenSSLDockerHelper(DockerClient dockerClient, boolean withCoverage){
        this.dockerClient = dockerClient;
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

    /**
     * Creates a docker tag. This tag is different, if the library name, the library version, or the cli option
     * string is different. The docker tags looks like:
     * _[LIB NAME]_[LIB VERSION]_[CLI OPTION HASH]
     *
     * the CLI_OPTION HASH is an hex string of the hash value over the cli option input string (required, because the
     * docker tag has a maximal length). Also, both LIB NAME and LIB VERSION are cut after the 20th character and illegal
     * docker tag characters are eliminated.
     *
     * @param cliOptions - The command line string that is passed the buildscript
     * @param libraryName - The name of the tls library (e.g. 'OpenSSL')
     * @param libraryVersion - The library's version (e.g. '1.1.1e')
     * @returns the resulting docker tag
     */
    public String computeDockerTag(List<String> cliOptions, String libraryName, String libraryVersion){
        String cliString = String.join("", cliOptions);
        String libraryVersionPart = libraryVersion.substring(0,Math.min(20, libraryVersion.length()));
        String cliStringHashString;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(cliString.getBytes());
            cliStringHashString = DatatypeConverter.printHexBinary(messageDigest.digest()).toLowerCase();
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new UnsupportedOperationException("Cannot create a docker tag.");
        }

        cliStringHashString = cliStringHashString.substring(0,Math.min(16, cliStringHashString.length()));

        String res = String.format("_%s_%s", libraryVersionPart, cliStringHashString);
        res = res.replaceAll("[^a-zA-Z0-9_\\.\\-]", "");
        return res;
    }

    public String getFactoryImageNameAndTag(String openSSLBranchName){
        return String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
    }

    public String getOpenSSLBuildImageNameAndTag(String dockerTag){
        return String.format("%s:%s",BUILD_REPRO_NAME, dockerTag);
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
            resultsCollector.logBuildContainer(new DockerContainerInfo(dockerTag, containerResp.getId(), DockerContainerState.RUNNING));
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
        String finalImageTag = String.format("%s:%s", BUILD_REPRO_NAME, dockerTag);
        dockerClient.buildImageCmd()
                .withDockerfile(dockerfileMinPath.toFile())
                .withTags(new HashSet<>(Arrays.asList(finalImageTag)))
                .withBuildArg("TEMP_REPRO", buildArg).exec(new BuildImageResultCallback()).awaitImageId();

        LOGGER.debug("Final Image built");

        // Remove the temporary image and container
        dockerClient.removeImageCmd(tempImageId).exec();
        dockerClient.removeContainerCmd(tempContainer.getId()).exec();
    }

    public DockerServerContainerInfo createDockerServer(String dockerTag,
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


        String dockerContainerId = createDockerContainer(dockerTag, entrypoint, portBindings, volumeBindings);
        DockerServerContainerInfo containerInfo = new DockerServerContainerInfo(dockerTag, dockerContainerId, DockerContainerState.NOT_RUNNING, dockerHost, dockerTlsPort, managerPort);

        return containerInfo;
    }

    public DockerClientContainerInfo createDockerClient(String dockerTag,
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

        String dockerContainerId = createDockerContainer(dockerTag, entrypoint, portBindings, volumeBindings);
        DockerClientContainerInfo containerInfo = new DockerClientContainerInfo(dockerTag, dockerContainerId, DockerContainerState.NOT_RUNNING,
                dockerManagerHost, dockeManagerPort);

        return containerInfo;
    }

    /**
     * Creates a docker container and returns the container id of the created container.
     *
     * @param dockerTag
     * @param entrypoint
     * @param portBindings
     * @param volumeBindings
     * @return the container id
     */
    public synchronized String createDockerContainer(String dockerTag,
                                                     List<String> entrypoint,
                                                     List<PortBinding> portBindings,
                                                     List<Bind> volumeBindings)
    {

        String imageTag = String.format("%s:%s", BUILD_REPRO_NAME, dockerTag);
        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);

        Optional<Container> oldContainer = containerByName(containerName);
        if(oldContainer.isPresent()){
            dockerClient.removeContainerCmd(oldContainer.get().getId()).withForce(true).exec();
            LOGGER.debug("Old Container Removed");
        }

        HostConfig hostConfig = HostConfig.newHostConfig()
                .withPortBindings(portBindings)
                .withDns(new ArrayList<String>())
                .withDnsOptions(new ArrayList<String>())
                .withDnsSearch(new ArrayList<String>())
                .withBlkioWeightDevice(new ArrayList<>())
                .withDevices(new ArrayList<Device>())
                .withExtraHosts("host.docker.internal:host-gateway")
                .withBinds(volumeBindings);

        List<ExposedPort> exposedPorts = new LinkedList<>();
        for(PortBinding portBinding : portBindings){
            exposedPorts.add(portBinding.getExposedPort());
        }


        CreateContainerResponse createContainerCmd = dockerClient.createContainerCmd(imageTag)
                .withName(containerName)
                // Some of these options lead to (very undetectable and annoying) errors if they aren't set.
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

    public void startContainer(DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() != DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot start a running (or paused) container.");
        }
        dockerClient.startContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.RUNNING);
    }

    public void stopContainer(DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() == DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot stop a stopped container.");
        }
        dockerClient.stopContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.NOT_RUNNING);
    }

    public void pauseContainer(DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() != DockerContainerState.RUNNING){
            throw new IllegalStateException("Cannot pause a non running container.");
        }
        dockerClient.pauseContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.PAUSED);
    }

    public void unpauseContainer(DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() != DockerContainerState.PAUSED){
            throw new IllegalStateException("Cannot unpause a non paused container.");
        }
        dockerClient.unpauseContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.RUNNING);
    }

    public void removeContainer(DockerContainerInfo containerInfo){
        dockerClient.removeContainerCmd(containerInfo.getContainerId()).withForce(true).exec();
        containerInfo.updateContainerState(DockerContainerState.INVALID);
    }

    private Optional<Container> containerByName(String name){
        final String cName;
        if(!name.startsWith("/")){
            cName = "/"+name;
        }
        else{
            cName = name;
        }
        Predicate<Container> pred = container -> Arrays.asList(container.getNames()).stream().anyMatch(n -> n.equals(cName));
        return dockerClient.listContainersCmd().withShowAll(true).exec().stream().filter(pred).findFirst();
    }



}
