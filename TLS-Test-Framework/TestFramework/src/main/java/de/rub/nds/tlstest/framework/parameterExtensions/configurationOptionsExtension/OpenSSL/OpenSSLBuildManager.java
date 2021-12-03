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
import com.github.dockerjava.api.model.*;
import com.github.dockerjava.core.DockerClientBuilder;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsscanner.serverscanner.TlsScanner;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigOptionValueTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.FlagTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.PortRange;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;

/**
 * The OpenSSLBuildManager is a ConfigurationOptionsBuildManager to build modern OpenSSL versions.
 */
public class OpenSSLBuildManager implements ConfigurationOptionsBuildManager {

    private Map<String, TestSiteReport> dockerTagToSiteReport;
    private Map<String, DockerContainerInfo> dockerTagToContainerInfo;
    private Set<Integer> usedPorts;

    private Set<String> existingDockerImageNameWithTags;
    private DockerClient dockerClient;

    private Path dockerfileMinPath;

    private ConfigurationOptionsConfig configOptionsConfig;

    private final String CCACHE_VOLUME_NAME = "ccache-cache";

    // TODO: Currently Server-Only

    public OpenSSLBuildManager(ConfigurationOptionsConfig configurationOptionsConfig){
        configOptionsConfig = configurationOptionsConfig;

        usedPorts = new HashSet<>();
        dockerTagToSiteReport = new HashMap<>();
        dockerTagToContainerInfo = new HashMap<>();
        initDocker();
    }

    public DockerClient getDockerClient() {
        return dockerClient;
    }

    public void initDocker(){

        dockerClient = DockerClientBuilder.getInstance().build();

        // Get all existing docker tags
        // Note that it is assumed, that no (relevant) docker images are created or deleted manually during the test executions
        List<Image> imageList = dockerClient.listImagesCmd().withDanglingFilter(false).exec();
        existingDockerImageNameWithTags = new HashSet<>();
        for(Image img : imageList){
            Object tagsObj = img.getRawValues().get("RepoTags");
            List<String> tags = (List<String>) tagsObj;
            existingDockerImageNameWithTags.addAll(tags);
        }

        // Create a ccache volume if it does not exist so far
        if(!dockerClient.listVolumesCmd().exec().getVolumes().stream().anyMatch(response -> response.getName().equals(CCACHE_VOLUME_NAME))){
            // If a volume with the specified name exists:
            dockerClient.createVolumeCmd().withName(CCACHE_VOLUME_NAME).exec();
        }

        // Find dockerfile paths
        Path dockerLibraryPath = configOptionsConfig.getDockerLibraryPath();

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

        // Build the factory if it does not exist

        // Note that the library name must be a branch in OpenSSL's github.
        String openSSLBranchName = configOptionsConfig.getTlsVersionName();
        String factoryImageNameWithTag = OpenSSLDockerHelper.getFactoryImageNameAndTag(openSSLBranchName);
        if(!dockerNameWithTagExists(factoryImageNameWithTag)){
            OpenSSLDockerHelper.createFactoryImage(dockerClient, pathToFactoryDockerfile, openSSLBranchName);
        }

        dockerfileMinPath = pathToMinDockerfile;

        // On shutdown: Clean all created docker containers
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            for (Map.Entry<String, DockerContainerInfo> entry : dockerTagToContainerInfo.entrySet()) {
                OpenSSLDockerHelper.removeContainer(dockerClient, entry.getValue());
            }
        }));

    }

    @Override
    public TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet) {
        String buildTag =  provideOpenSSLImplementation(optionSet);
        DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(buildTag);
        TestSiteReport report = dockerTagToSiteReport.get(buildTag);

        // Configure the port in the config
        OutboundConnection connection = new OutboundConnection(containerInfo.getPort(), configOptionsConfig.getDockerHostName());
        config.setDefaultClientConnection(connection);//.setPort(containerInfo.getPort());

        //OpenSSLDockerHelper.printContainerLogDebug(dockerClient, containerInfo.getContainerId());

        return report;
    }

    @Override
    public TestSiteReport createSiteReportFromOptionSet(Set<ConfigurationOptionDerivationParameter> optionSet) {
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        String dockerTag = OpenSSLDockerHelper.computeDockerTag(cliOptions, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsVersionName());
        String dockerNameWithTag = OpenSSLDockerHelper.getOpenSSLBuildImageNameAndTag(dockerTag);
        if(!dockerNameWithTagExists(dockerNameWithTag)){
            OpenSSLDockerHelper.buildOpenSSLImageWithFactory(dockerClient, cliOptions, dockerTag, dockerfileMinPath, configOptionsConfig.getTlsVersionName(), CCACHE_VOLUME_NAME);
        }
        TestSiteReport report;
        if(!dockerTagToSiteReport.containsKey(dockerTag)){
            report = createSiteReport(dockerTag);
            dockerTagToSiteReport.put(dockerTag, report);
        }
        else{
            report = dockerTagToSiteReport.get(dockerTag);
        }
        return report;
    }

    /**
     * Starts a docker container with the given options
     *
     * @param optionSet - the options set to use
     * @returns the dockerTag for the created implementation. The tag can be used to find the created container and the TestSiteReport.
     */
    private String provideOpenSSLImplementation(Set<ConfigurationOptionDerivationParameter> optionSet){
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        String dockerTag = OpenSSLDockerHelper.computeDockerTag(cliOptions, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsVersionName());
        String dockerNameWithTag = OpenSSLDockerHelper.getOpenSSLBuildImageNameAndTag(dockerTag);
        DockerContainerInfo providedContainer;

        // Case: A docker container already exists
        if(dockerTagToContainerInfo.containsKey(dockerTag)){
            providedContainer = dockerTagToContainerInfo.get(dockerTag);
            if(providedContainer.getContainerState() == DockerContainerState.NOT_RUNNING) {
                OpenSSLDockerHelper.startContainer(dockerClient, providedContainer);
            }
            else if(providedContainer.getContainerState() == DockerContainerState.PAUSED){
                OpenSSLDockerHelper.unpauseContainer(dockerClient, providedContainer);
            }
        }
        // Case: A new container has to be created
        else{
            // SubCase: The image for the container does not already exists
            if(!dockerNameWithTagExists(dockerNameWithTag)){
                OpenSSLDockerHelper.buildOpenSSLImageWithFactory(dockerClient, cliOptions, dockerTag, dockerfileMinPath, configOptionsConfig.getTlsVersionName(), CCACHE_VOLUME_NAME);
                existingDockerImageNameWithTags.add(dockerNameWithTag);
            }
            // Sub Case: There is no SiteReport created yet.
            if(!dockerTagToSiteReport.containsKey(dockerTag)){
                TestSiteReport report = createSiteReport(dockerTag);
                dockerTagToSiteReport.put(dockerTag, report);
            }
            providedContainer = OpenSSLDockerHelper.createDockerContainerServer(dockerClient, dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort());
            OpenSSLDockerHelper.startContainer(dockerClient, providedContainer);
            dockerTagToContainerInfo.put(dockerTag, providedContainer);
        }

        return dockerTag;
    }

    public TestSiteReport createSiteReport(String dockerTag){
        DockerContainerInfo container = OpenSSLDockerHelper.createDockerContainerServer(dockerClient, dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort());
        OpenSSLDockerHelper.startContainer(dockerClient, container);

        TestConfig testConfig = new TestConfig();
        testConfig.setTestEndpointMode(TestEndpointType.SERVER);

        testConfig.getTestServerDelegate().setHost(configOptionsConfig.getDockerHostName()+":"+container.getPort());

        ScannerConfig scannerConfig = new ScannerConfig(testConfig.getGeneralDelegate(), testConfig.getTestServerDelegate());
        scannerConfig.setTimeout(testConfig.getConnectionTimeout());
        Config config = scannerConfig.createConfig();
        config.setAddServerNameIndicationExtension(testConfig.createConfig().isAddServerNameIndicationExtension());

        config.getDefaultClientConnection().setConnectionTimeout(0);
        scannerConfig.setBaseConfig(config);

        scannerConfig.setProbes(
                ProbeType.COMMON_BUGS,
                ProbeType.CIPHER_SUITE,
                ProbeType.CERTIFICATE,
                ProbeType.COMPRESSIONS,
                ProbeType.NAMED_GROUPS,
                ProbeType.PROTOCOL_VERSION,
                ProbeType.EC_POINT_FORMAT,
                ProbeType.RESUMPTION,
                ProbeType.EXTENSIONS,
                ProbeType.RECORD_FRAGMENTATION,
                ProbeType.HELLO_RETRY
        );
        scannerConfig.setOverallThreads(1);
        scannerConfig.setParallelProbes(1);

        TlsScanner scanner = new TlsScanner(scannerConfig);

        TestSiteReport report = TestSiteReport.fromSiteReport(scanner.scan());

        // Remove container
        OpenSSLDockerHelper.removeContainer(dockerClient, container);
        freeOccupiedPort(container.getPort());

        return report;
    }

    private List<String> createConfigOptionCliList(Set<ConfigurationOptionDerivationParameter> optionSet){
        Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> optionsToTranslationMap = configOptionsConfig.getOptionsToTranslationMap();
        List<String> optionsCliList = new ArrayList<>();
        for(ConfigurationOptionDerivationParameter optionParameter : optionSet){
            String cliOption = translateOptionValue(optionParameter, optionsToTranslationMap).trim();
            if(!cliOption.isEmpty()){
                optionsCliList.add(cliOption);
            }
        }
        // Sort the options alphabetically. This is used to obtain deterministic results independent of the Set's iteration order.
        optionsCliList.sort(Comparator.comparing(String::toString));

        return optionsCliList;
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
    private boolean dockerNameWithTagExists(String dockerTag){
        return existingDockerImageNameWithTags.contains(dockerTag);
    }

    private Integer occupyNextPort(){
        PortRange portRange = configOptionsConfig.getDockerPortRange();
        Integer port;
        boolean portFound = false;
        for(port =  portRange.getMinPort(); port <= portRange.getMaxPort(); port++){
            if(usedPorts.contains(port)){
                continue;
            }
            else{
                portFound = true;
                break;
            }
        }
        if(!portFound){
            throw new RuntimeException("Port range exhausted.");
        }

        usedPorts.add(port);
        return port;
    }

    private void freeOccupiedPort(Integer port){
        usedPorts.remove(port);
    }

}
