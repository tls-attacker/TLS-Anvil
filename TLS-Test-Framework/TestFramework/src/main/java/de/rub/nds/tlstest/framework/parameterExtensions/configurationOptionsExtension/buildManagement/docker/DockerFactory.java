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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Predicate;

public abstract class DockerFactory {
    private static final Logger LOGGER = LogManager.getLogger();
    protected DockerClient dockerClient;
    protected String BUILD_REPRO_NAME;
    protected String CONTAINER_NAME_PREFIX;



    public DockerFactory(DockerClient dockerClient, String buildReproName){
        this.dockerClient = dockerClient;
        this.BUILD_REPRO_NAME = buildReproName;
        this.CONTAINER_NAME_PREFIX = "container";
    }

    public void init(){

    }

    public abstract DockerClientTestContainer createDockerClient(String dockerTag,
                                                        String dockerManagerHost,
                                                        Integer dockeManagerPort,
                                                        String tlsServerHost,
                                                        Integer tlsServerPort);



    public abstract DockerServerTestContainer createDockerServer(String dockerTag,
                                                                 String dockerHost,
                                                                 Integer dockerTlsPort,
                                                                 Integer managerPort);

    public String getOpenSSLBuildImageNameAndTag(String dockerTag){
        return String.format("%s:%s",BUILD_REPRO_NAME, dockerTag);
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
     * @param libraryNameAndVersion - The library's version (e.g. '1.1.1e')
     * @returns the resulting docker tag
     */
    public static String computeDockerTag(List<String> cliOptions, String libraryNameAndVersion){
        String cliString = String.join("", cliOptions);
        String libraryVersionPart = libraryNameAndVersion.substring(0,Math.min(20, libraryNameAndVersion.length()));
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


    /**
     * Creates a docker container and returns the container id of the created container.
     *
     * @param dockerImageTag
     * @param entrypoint
     * @param portBindings
     * @param volumeBindings
     * @return the container id
     */
    public synchronized String createDockerContainer(String dockerImageTag,
                                                     List<String> entrypoint,
                                                     List<PortBinding> portBindings,
                                                     List<Bind> volumeBindings,
                                                     String containerName)
    {

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


        CreateContainerResponse createContainerCmd = dockerClient.createContainerCmd(dockerImageTag)
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

    protected Optional<Container> containerByName(String name){
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
