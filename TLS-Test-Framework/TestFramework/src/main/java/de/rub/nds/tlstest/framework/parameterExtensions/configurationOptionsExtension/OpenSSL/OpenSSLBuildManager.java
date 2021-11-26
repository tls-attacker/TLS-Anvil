/**
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
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.BuildImageResultCallback;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.core.command.LogContainerResultCallback;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.List;
import java.util.function.Predicate;

/**
 * The OpenSSLBuildManager is a ConfigurationOptionsBuildManager to build modern OpenSSL versions.
 */
public class OpenSSLBuildManager implements ConfigurationOptionsBuildManager {
    private static OpenSSLBuildManager instance = null;
    private Path buildScriptPath;
    private Map<String, TestSiteReport> dockerTagToSiteReport;

    private Set<String> existingDockerTags;
    private DockerClient dockerClient;

    private Path dockerfileFactoryPath;
    private Path dockerfileMinPath;

    private Path dockerLibraryPath = Paths.get("/home/fabian/TLS-Docker-Library/"); // TODO: Take from config
    private String openSSLBranchName = "OpenSSL_1_1_1"; // TODO: Take from config

    private boolean dockerInitialized;

    // Constant Strings for docker
    private final String CCACHE_VOLUME_NAME = "ccache-cache";
    private final String FACTORY_REPRO_NAME = "openssl-factory";
    private final String TEMP_CONTAINER_NAME = "temp-openssl-container";
    private final String TEMP_REPRO_NAME = "temp_openssl_img";
    private final String BUILD_REPRO_NAME = "openssl_img";
    private final String CONTAINER_NAME_PREFIX = "openssl";

    private Volume targetVolume = new Volume("/src/ccache");


    public static synchronized OpenSSLBuildManager getInstance() {
        if (OpenSSLBuildManager.instance == null) {
            OpenSSLBuildManager.instance = new OpenSSLBuildManager();
        }
        return OpenSSLBuildManager.instance;
    }

    private OpenSSLBuildManager(){
        dockerTagToSiteReport = new HashMap<>();
        dockerInitialized = false;
    }

    private void initDocker(){
        // The log4j logger must be disabled to prevent warnings of unconfigured log4j
        Logger.getRootLogger().setLevel(Level.OFF);
        dockerClient = DockerClientBuilder.getInstance().build();

        // Get all existing docker tags
        // Note that it is assumed, that no (relevant) docker images are created or deleted manually during the test executions
        List<Image> imageList = dockerClient.listImagesCmd().withDanglingFilter(false).exec();
        existingDockerTags = new HashSet<>();
        for(Image img : imageList){
            Object tagsObj = img.getRawValues().get("RepoTags");
            List<String> tags = (List<String>) tagsObj;
            existingDockerTags.addAll(tags);
        }

        // Create a ccache volume if it does not exist so far
        if(!dockerClient.listVolumesCmd().exec().getVolumes().stream().anyMatch(response -> response.getName().equals(CCACHE_VOLUME_NAME))){
            // If a volume with the specified name exists:
            dockerClient.createVolumeCmd().withName(CCACHE_VOLUME_NAME).exec();
        }

        // Find dockerfile paths
        Path partialPathToFactoryDockerfile = Paths.get("images", "openssl", "configurationOptionsFactory", "Dockerfile_Factory_OpenSSL");
        Path pathToFactoryDockerfile = dockerLibraryPath.resolve(partialPathToFactoryDockerfile);

        Path partialPathToMinDockerfile = Paths.get("images", "openssl", "configurationOptionsFactory", "Dockerfile_Min_OpenSSL");
        Path pathToMinDockerfile = dockerLibraryPath.resolve(partialPathToMinDockerfile);

        if(!Files.exists(pathToMinDockerfile)){
            throw new RuntimeException(
                    String.format("Dockerfile '%s' does not exist. Have you configured the right Docker Library path? " +
                            "Or are you using an old DockerLibrary Version?", pathToMinDockerfile.toString()));
        }


        if(!Files.exists(pathToFactoryDockerfile)){
            throw new RuntimeException(
                    String.format("Dockerfile '%s' does not exist. Have you configured the right Docker Library path? " +
                            "Or are you using an old DockerLibrary Version?", pathToFactoryDockerfile.toString()));
        }

        dockerfileFactoryPath = pathToFactoryDockerfile;
        dockerfileMinPath = pathToMinDockerfile;
        dockerInitialized = true;
    }

    @Override
    public TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet) {
        // Initializes docker if called for the first time
        if(!dockerInitialized){
            initDocker();
        }

        ConfigurationOptionsConfig configOptionsConfig = ConfigurationOptionsDerivationManager.getInstance().getConfigurationOptionsConfig();
        if(configOptionsConfig == null){
            throw new IllegalStateException("No config option configuration configured yet.");
        }
        Integer port = provideOpenSSLImplementation(configOptionsConfig, optionSet);

        // TODO: Configure port and check for TestSiteReport
        return null;
    }


    /*private Integer provideOpenSSLServerImplementation(ConfigurationOptionsConfig configOptionsConfig, Set<ConfigurationOptionDerivationParameter> optionSet){
        // TODO
        return -1;
    }*/

    private Integer provideOpenSSLImplementation(ConfigurationOptionsConfig configOptionsConfig, Set<ConfigurationOptionDerivationParameter> optionSet){
        String cliString = createConfigOptionCliString(optionSet, configOptionsConfig);
        String dockerTag = computeDockerTag(cliString, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsLibraryVersion());

        if(!dockerTagExists(dockerTag)){
            buildDockerImage(cliString, dockerTag);
        }

        // TODO: start container and assign port

        return -1;
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
     * @param cliString - The command line string that is passed the buildscript
     * @param libraryName - The name of the tls library (e.g. 'OpenSSL')
     * @param libraryVersion - The library's version (e.g. '1.1.1e')
     * @returns the resulting docker tag
     */
    private static String computeDockerTag(String cliString, String libraryName, String libraryVersion){
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

        String res = String.format("_%s_%s", libraryVersionPart, cliStringHashString);
        res = res.replaceAll("[^a-zA-Z0-9_\\.\\-]", "");
        return res;
    }

    private String createConfigOptionCliString(Set<ConfigurationOptionDerivationParameter> optionSet, ConfigurationOptionsConfig configOptionsConfig){
        Map<ConfigOptionDerivationType,ConfigOptionValueTranslation> optionsToTranslationMap = configOptionsConfig.getOptionsToTranslationMap();
        List<String> optionsCliList = new ArrayList<>();
        for(ConfigurationOptionDerivationParameter optionParameter : optionSet){
            String cliOption = translateOptionValue(optionParameter, optionsToTranslationMap).trim();
            if(!cliOption.isEmpty()){
                optionsCliList.add(cliOption);
            }
        }
        // Sort the options alphabetically. This is used to obtain deterministic results independent of the Set's iteration order.
        optionsCliList.sort(Comparator.comparing(String::toString));

        return String.join(" ", optionsCliList);
    }

    private String translateOptionValue(ConfigurationOptionDerivationParameter optionParameter, Map<ConfigOptionDerivationType,ConfigOptionValueTranslation> optionsToTranslationMap){
        ConfigurationOptionValue value = optionParameter.getSelectedValue();
        if(value == null){
            throw new IllegalArgumentException("Passed option parameter has no selected value yet.");
        }
        DerivationType derivationType = optionParameter.getType();
        if(!(derivationType instanceof ConfigOptionDerivationType)){
            throw new IllegalArgumentException("Passed derivation parameter is not of type ConfigOptionDerivationType.");
        }
        ConfigOptionDerivationType optionType = (ConfigOptionDerivationType) derivationType;

        if(!optionsToTranslationMap.containsKey(optionType)){
            throw new IllegalStateException("The ConfigurationOptionsConfig's translation map does not contain the passed type");
        }

        ConfigOptionValueTranslation translation = optionsToTranslationMap.get(optionType);

        if(translation instanceof FlagTranslation){
            FlagTranslation flagTranslation = (FlagTranslation) translation;
            if(!value.isFlag()){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation is a flag, but the ConfigurationOptionValue isn't. Value can't be translated.");
            }

            if(value.isOptionSet()){
                return flagTranslation.getDataIfSet();
            }
            else{
                return flagTranslation.getDataIfNotSet();
            }
        }
        else{
            throw new UnsupportedOperationException(String.format("The OpenSSLBuildManager does not support translations '%s'.", translation.getClass()));
        }

    }

    // Docker access functions

    private boolean dockerTagExists(String dockerTag){
        return existingDockerTags.contains(dockerTag);
    }


    public synchronized void buildDockerImage(String cliOptionString, String dockerTag)  {
        if(!dockerInitialized){
            initDocker();
        }

        // Create the docker factory image for the respective OpenSSL version, if it does not exist so far
        String factoryImageTag = String.format("%s:%s",FACTORY_REPRO_NAME, openSSLBranchName);
        if(!dockerTagExists(factoryImageTag)){
            System.out.println("Build factory image.");
            dockerClient.buildImageCmd()
                    .withDockerfile(dockerfileFactoryPath.toFile())
                    .withTags(new HashSet<>(Arrays.asList(factoryImageTag)))
                    .withBuildArg("OPENSSL_BRANCH", openSSLBranchName).exec(new BuildImageResultCallback()).awaitImageId();
        }

        // Remove old containers (TODO: Only needs to be done if something went wrong)
        Optional<Container> oldTempContainer = containerByName(TEMP_CONTAINER_NAME);
        if(oldTempContainer.isPresent()){
            dockerClient.removeContainerCmd(oldTempContainer.get().getId()).exec();
            System.out.println("Old Container Removed");
        }

        // Create a temporary container to build OpenSSL using ccache (TODO: with volumes?)
        CreateContainerResponse tempContainer = dockerClient.createContainerCmd(factoryImageTag)
                .withName(TEMP_CONTAINER_NAME)
                .withHostConfig(HostConfig.newHostConfig().withBinds(new Bind(CCACHE_VOLUME_NAME, targetVolume)))
                .withCmd(cliOptionString)
                .exec();

        System.out.println("Factory Container created.");

        // Start the created container
        dockerClient.startContainerCmd(tempContainer.getId()).exec();
        InspectContainerResponse containerResp
                = dockerClient.inspectContainerCmd(tempContainer.getId()).exec();

        System.out.println("Factory Container started.");

        // Wait for the build process to finish and the container stops
        while(containerResp.getState().getRunning()){
            try {
                Thread.sleep(1000);
                containerResp = dockerClient.inspectContainerCmd(tempContainer.getId()).exec();
                //System.out.println(containerResp.getState());
                System.out.println(".");
            }
            catch(InterruptedException e){
                e.printStackTrace();
            }
        }

        System.out.println("\nFactory Container finished.");

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

        System.out.println("Final Image built");

        // Remove the temporary image and container
        dockerClient.removeImageCmd(tempImageId).exec();
        dockerClient.removeContainerCmd(tempContainer.getId()).exec();

        existingDockerTags.add(dockerTag);
    }

    public Optional<Container> containerByName(String name){
        final String cName;
        if(!name.startsWith("/")){
            cName = "/"+name;
        }
        else{
            cName = name;
        }

        for(Container c : dockerClient.listContainersCmd().exec()){
            System.out.println(Arrays.asList(c.getNames()));
        }
        //System.out.println(Arrays.asList(container.getNames()));


        Predicate<Container> pred = container -> Arrays.asList(container.getNames()).stream().anyMatch(n -> n.equals(cName));
        return dockerClient.listContainersCmd().withShowAll(true).exec().stream().filter(pred).findFirst();
    }

    public String startDockerContainerServer(String dockerTag, String ipAddress, Integer port){
        if(!dockerInitialized){
            initDocker();
        }

        //TODO: Remove debug prints

        String imageTag = String.format("%s:%s", BUILD_REPRO_NAME, dockerTag);
        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);

        Optional<Container> oldContainer = containerByName(containerName);
        if(oldContainer.isPresent()){
            dockerClient.removeContainerCmd(oldContainer.get().getId()).exec();
            System.out.println("Old Container Removed");
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

        System.out.println("Container created.");

        dockerClient.startContainerCmd(createContainerCmd.getId()).exec();

        System.out.println("Container started.");

        return createContainerCmd.getId();
    }

    // Debug only
    public void printContainerLogDebug(String containerId){
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
}
