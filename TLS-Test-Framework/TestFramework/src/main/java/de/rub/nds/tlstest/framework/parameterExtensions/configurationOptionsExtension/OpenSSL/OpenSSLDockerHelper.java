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
import com.github.dockerjava.core.command.LogContainerResultCallback;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Predicate;

public class OpenSSLDockerHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String FACTORY_REPRO_NAME = "openssl-factory";
    private static final String TEMP_CONTAINER_NAME = "temp-openssl-container";
    private static final String TEMP_REPRO_NAME = "temp_openssl_img";
    private static final String BUILD_REPRO_NAME = "openssl_img";
    private static final String CONTAINER_NAME_PREFIX = "container";

    private static Volume targetVolume = new Volume("/src/ccache");


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
    public static String computeDockerTag(List<String> cliOptions, String libraryName, String libraryVersion){
        String cliString = String.join("", cliOptions);
        //String libraryNamePart = libraryName.substring(0, Math.min(20, libraryName.length()));
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

    public static String getFactoryImageTag(String openSSLBranchName){
        return String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
    }

    public static synchronized void buildOpenSSLImageWithFactory(DockerClient dockerClient, List<String> cliOptions, String dockerTag, Path dockerfileMinPath, String openSSLBranchName, String ccacheVolumeName)  {
        LOGGER.debug(String.format("Build with option string: '%s'", cliOptions));

        // Create the docker factory image for the respective OpenSSL version, if it does not exist so far
        String factoryImageTag = String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);

        // Remove old containers (Only needs to be done if something went wrong)
        Optional<Container> oldTempContainer = containerByName(dockerClient, TEMP_CONTAINER_NAME);
        if(oldTempContainer.isPresent()){
            dockerClient.removeContainerCmd(oldTempContainer.get().getId()).exec();
            LOGGER.debug("Old Container Removed");
        }

        // Create a temporary container to build OpenSSL using ccache (TODO: with volumes?)
        CreateContainerResponse tempContainer = dockerClient.createContainerCmd(factoryImageTag)
                .withName(TEMP_CONTAINER_NAME)
                .withHostConfig(HostConfig.newHostConfig().withBinds(new Bind(ccacheVolumeName, targetVolume)))
                .withCmd(cliOptions)
                .exec();

        LOGGER.debug("Factory Container created.");

        // Start the created container
        dockerClient.startContainerCmd(tempContainer.getId()).exec();
        InspectContainerResponse containerResp
                = dockerClient.inspectContainerCmd(tempContainer.getId()).exec();

        // TODO tmp
        printContainerLogDebug(dockerClient, containerResp.getId());

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

    private static Optional<Container> containerByName(DockerClient dockerClient, String name){
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

    // For Debugging
    public static void printContainerLogDebug(DockerClient dockerClient, String containerId){
        List<String> logs = new ArrayList<>();
        System.out.println(String.format("===== Output of Docker Container (id = %s) =====", containerId));
        try {
            dockerClient.logContainerCmd(containerId).withStdOut(true).
                    withStdErr(true).withFollowStream(true).exec(new LogContainerResultCallback() {
                @Override
                public void onNext(Frame item) {
                    System.out.print(new String(item.getPayload()));
                }
            }).awaitCompletion();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("===== End: Output of Docker Container =====");
    }

    private static String computerContainerName(String dockerTag, String ipAddress, Integer port){
        String ipAddressPart = ipAddress.replaceAll("[^a-zA-Z0-9_\\.\\-]", "");
        String res = String.format("%s%s_%s_%d", CONTAINER_NAME_PREFIX, dockerTag, ipAddressPart, port);

        return res;
    }

    public static DockerContainerInfo createDockerContainerServer(DockerClient dockerClient, String dockerTag, String ipAddress, Integer port){

        String imageTag = String.format("%s:%s", BUILD_REPRO_NAME, dockerTag);
        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);

        Optional<Container> oldContainer = containerByName(dockerClient, containerName);
        if(oldContainer.isPresent()){
            dockerClient.removeContainerCmd(oldContainer.get().getId()).withForce(true).exec();
            LOGGER.debug("Old Container Removed");
        }

        final Integer CONTAINER_PORT = 443;
        ExposedPort exposedPort = ExposedPort.tcp(CONTAINER_PORT);

        PortBinding portBinding = new PortBinding(Ports.Binding.bindIpAndPort(ipAddress, port), exposedPort);

        Volume destVolume = new Volume("/cert/");

        HostConfig hostConfig = HostConfig.newHostConfig()
                .withPortBindings(portBinding)
                .withDns(new ArrayList<String>())
                .withDnsOptions(new ArrayList<String>())
                .withDnsSearch(new ArrayList<String>())
                .withBlkioWeightDevice(new ArrayList<>())
                .withDevices(new ArrayList<Device>())
                .withBinds(new Bind("cert-data", destVolume, AccessMode.ro, SELContext.DEFAULT, true));


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
                .withExposedPorts(exposedPort)
                .withCmd(Arrays.asList("-accept", CONTAINER_PORT.toString(), "-key", "/cert/ec256key.pem", "-cert", "/cert/ec256cert.pem"))
                .exec();

        DockerContainerInfo containerInfo = new DockerContainerInfo(dockerTag, createContainerCmd.getId(), DockerContainerState.NOT_RUNNING, port);
        LOGGER.debug("Container created.");

        return containerInfo;
    }

    public static String createFactoryImage(DockerClient dockerClient, Path dockerfileFactoryPath, String openSSLBranchName){
        // Create the docker factory image for the respective OpenSSL version, if it does not exist so far
        String factoryImageTag = String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
        LOGGER.debug("Build factory image.");
        dockerClient.buildImageCmd()
                .withDockerfile(dockerfileFactoryPath.toFile())
                .withTags(new HashSet<>(Arrays.asList(factoryImageTag)))
                .withBuildArg("OPENSSL_BRANCH", openSSLBranchName).exec(new BuildImageResultCallback()).awaitImageId();

        return factoryImageTag;
    }

    public static void startContainer(DockerClient dockerClient, DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() != DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot start a running (or paused) container.");
        }
        dockerClient.startContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.RUNNING);
    }

    public static void stopContainer(DockerClient dockerClient, DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() == DockerContainerState.NOT_RUNNING){
            throw new IllegalStateException("Cannot stop a stopped container.");
        }
        dockerClient.stopContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.NOT_RUNNING);
    }

    public static void pauseContainer(DockerClient dockerClient, DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() != DockerContainerState.RUNNING){
            throw new IllegalStateException("Cannot pause a non running container.");
        }
        dockerClient.pauseContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.PAUSED);
    }

    public static void unpauseContainer(DockerClient dockerClient, DockerContainerInfo containerInfo){
        if(containerInfo.getContainerState() != DockerContainerState.PAUSED){
            throw new IllegalStateException("Cannot unpause a non paused container.");
        }
        dockerClient.unpauseContainerCmd(containerInfo.getContainerId()).exec();
        containerInfo.updateContainerState(DockerContainerState.RUNNING);
    }

    public static void removeContainer(DockerClient dockerClient, DockerContainerInfo containerInfo){
        dockerClient.removeContainerCmd(containerInfo.getContainerId()).withForce(true).exec();
        containerInfo.updateContainerState(DockerContainerState.INVALID);
    }

}
