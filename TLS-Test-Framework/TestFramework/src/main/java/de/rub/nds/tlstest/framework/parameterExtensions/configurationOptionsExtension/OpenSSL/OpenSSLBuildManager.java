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
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.transport.DockerHttpClient;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.util.ConsoleLogger;
import de.rub.nds.tlsscanner.serverscanner.ThreadedScanJobExecutor;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector.OpenSSLConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigOptionValueTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.FlagTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.PortRange;
import net.bytebuddy.dynamic.loading.ClassInjector;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.filter.ThresholdFilter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The OpenSSLBuildManager is a ConfigurationOptionsBuildManager to build modern OpenSSL versions.
 */
public class OpenSSLBuildManager extends ConfigurationOptionsBuildManager {

    private static final Logger LOGGER = LogManager.getLogger();
    private Filter noErrorAndWarningsFilter;


    private Map<String, TestSiteReport> dockerTagToSiteReport;
    private Map<String, DockerContainerInfo> dockerTagToContainerInfo;
    private Set<Integer> usedPorts;

    private Set<String> existingDockerImageNameWithTags;
    private DockerClient dockerClient;
    private OpenSSLConfigOptionsResultsCollector resultsCollector;

    private Path dockerfileMinPath;

    private ConfigurationOptionsConfig configOptionsConfig;

    private final String CCACHE_VOLUME_NAME = "ccache-cache";

    private final List<String> TRIGGER_COMMAND_PREFIX = Arrays.asList("curl");

    private final String TLS_SERVER_HOST;

    public OpenSSLBuildManager(ConfigurationOptionsConfig configurationOptionsConfig){
        //ThreadedScanJobExecutor tsje;
        configOptionsConfig = configurationOptionsConfig;
        usedPorts = new HashSet<>();
        dockerTagToSiteReport = new HashMap<>();
        dockerTagToContainerInfo = new HashMap<>();
        TLS_SERVER_HOST = configurationOptionsConfig.getDockerClientDestinationHostName();
    }

    public DockerClient getDockerClient() {
        return dockerClient;
    }

    public void setOpenSSLTriggerScript(){
        TestContext.getInstance().getConfig().getTestClientDelegate().setTriggerScript(getOpenSSLClientTriggerScript());
    }

    @Override
    public void init(){
        noErrorAndWarningsFilter = ThresholdFilter.createFilter( Level.ERROR, Filter.Result.ACCEPT, Filter.Result.DENY );

        setOpenSSLTriggerScript();
        //dockerClient = DockerClientBuilder.getInstance().build();



        DefaultDockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder().build();

        DockerHttpClient httpClient = (new com.github.dockerjava.jaxrs.JerseyDockerHttpClient.Builder()).dockerHost(config.getDockerHost()).sslConfig(config.getSSLConfig()).build();

        dockerClient = DockerClientBuilder
                .getInstance(config)
                .withDockerHttpClient(httpClient)
                .build();






        resultsCollector = new OpenSSLConfigOptionsResultsCollector(Paths.get(TestContext.getInstance().getConfig().getOutputFolder()), configOptionsConfig, dockerClient);

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

    }

    @Override
    public synchronized TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet) {
        String buildTag =  provideOpenSSLImplementation(optionSet);
        DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(buildTag);
        TestSiteReport report = dockerTagToSiteReport.get(buildTag);

        // Configure the port in the config
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
            DockerServerContainerInfo servercontainerInfo = (DockerServerContainerInfo) containerInfo;
            OutboundConnection connection = new OutboundConnection(servercontainerInfo.getTlsServerPort(), configOptionsConfig.getDockerHostName());
            config.setDefaultClientConnection(connection);
        }
        else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
            DockerClientContainerInfo clientContainerInfo = (DockerClientContainerInfo) containerInfo;

            InboundConnectionWithCustomTriggerArgs inboundConnectionWCTA = createTriggerConnectionForContainer(clientContainerInfo, config);
            config.setDefaultServerConnection(inboundConnectionWCTA);
        }
        else{
            throw new IllegalStateException("TestEndpointMode is invalid.");
        }

        return report;
    }

    @Override
    public synchronized TestSiteReport createSiteReportFromOptionSet(Set<ConfigurationOptionDerivationParameter> optionSet) {
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        String dockerTag = OpenSSLDockerHelper.computeDockerTag(cliOptions, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsVersionName());
        String dockerNameWithTag = OpenSSLDockerHelper.getOpenSSLBuildImageNameAndTag(dockerTag);
        if(!dockerNameWithTagExists(dockerNameWithTag)){
            OpenSSLDockerHelper.buildOpenSSLImageWithFactory(dockerClient, cliOptions, dockerTag, dockerfileMinPath, configOptionsConfig.getTlsVersionName(), CCACHE_VOLUME_NAME, resultsCollector);
            existingDockerImageNameWithTags.add(dockerNameWithTag);
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

    @Override
    public synchronized void onShutdown(){
        resultsCollector.finalizeResults();
        // Clear all created containers
        for (Map.Entry<String, DockerContainerInfo> entry : dockerTagToContainerInfo.entrySet()) {
            OpenSSLDockerHelper.removeContainer(dockerClient, entry.getValue());
        }
    }

    /**
     * Starts a docker container with the given options
     *
     * @param optionSet - the options set to use
     * @returns the dockerTag for the created implementation. The tag can be used to find the created container and the TestSiteReport.
     */
    private synchronized String provideOpenSSLImplementation(Set<ConfigurationOptionDerivationParameter> optionSet){
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
                long timer = System.currentTimeMillis();
                OpenSSLDockerHelper.buildOpenSSLImageWithFactory(dockerClient, cliOptions, dockerTag, dockerfileMinPath, configOptionsConfig.getTlsVersionName(), CCACHE_VOLUME_NAME, resultsCollector);
                resultsCollector.logNewOpenSSLBuildCreated(optionSet, dockerTag, System.currentTimeMillis() - timer);
                existingDockerImageNameWithTags.add(dockerNameWithTag);
            }
            // Sub Case: There is no SiteReport created yet.
            if(!dockerTagToSiteReport.containsKey(dockerTag)){
                TestSiteReport report = createSiteReport(dockerTag);
                dockerTagToSiteReport.put(dockerTag, report);
            }

            if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
                providedContainer = OpenSSLDockerHelper.createDockerClient(dockerClient, dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort(), TLS_SERVER_HOST, TestContext.getInstance().getConfig().getTestClientDelegate().getPort());
            }
            else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
                providedContainer = OpenSSLDockerHelper.createDockerServer(dockerClient, dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort());
            }
            else{
                throw new IllegalStateException("TestEndpointMode is invalid.");
            }

            OpenSSLDockerHelper.startContainer(dockerClient, providedContainer);
            resultsCollector.logOpenSSLContainer(providedContainer);
            dockerTagToContainerInfo.put(dockerTag, providedContainer);
        }
        resultsCollector.logBuildAccess(optionSet, dockerTag);
        return dockerTag;
    }

    public synchronized TestSiteReport createSiteReport(String dockerTag){
        TestSiteReport report;
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
            report = createClientSiteReport(dockerTag);
        }
        else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
            report = createServerSiteReport(dockerTag);
        }
        else{
            throw new IllegalStateException("TestEndpointMode is invalid.");
        }
        return report;
    }

    public synchronized TestSiteReport createServerSiteReport(String dockerTag){
        DockerServerContainerInfo container = OpenSSLDockerHelper.createDockerServer(dockerClient, dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort());
        OpenSSLDockerHelper.startContainer(dockerClient, container);

        TestSiteReport report = TestSiteReportFactory.createServerSiteReport(configOptionsConfig.getDockerHostName(), container.getTlsServerPort(), configOptionsConfig.isSiteReportConsoleLogDisabled());

        // Remove container
        OpenSSLDockerHelper.removeContainer(dockerClient, container);
        freeOccupiedPort(container.getTlsServerPort());

        return report;
    }

    public synchronized TestSiteReport createClientSiteReport(String dockerTag){
        Integer port = occupyNextPort();
        DockerClientContainerInfo container = OpenSSLDockerHelper.createDockerClient(dockerClient, dockerTag,configOptionsConfig.getDockerHostName(), port, TLS_SERVER_HOST, TestContext.getInstance().getConfig().getTestClientDelegate().getPort());
        OpenSSLDockerHelper.startContainer(dockerClient, container);

        Config config = TestContext.getInstance().getConfig().createConfig();
        InboundConnectionWithCustomTriggerArgs ibConnectionWCTA = createTriggerConnectionForContainer(container, config);
        TestSiteReport report =  TestSiteReportFactory.createClientSiteReport(TestContext.getInstance().getConfig(), ibConnectionWCTA, configOptionsConfig.isSiteReportConsoleLogDisabled());

        // Remove container
        OpenSSLDockerHelper.removeContainer(dockerClient, container);
        freeOccupiedPort(container.getManagerPort());

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

    private InboundConnectionWithCustomTriggerArgs createTriggerConnectionForContainer(DockerClientContainerInfo clientContainerInfo, Config config){
        InboundConnectionWithCustomTriggerArgs inboundConnectionWCTA = new InboundConnectionWithCustomTriggerArgs(config.getDefaultServerConnection());
        inboundConnectionWCTA.setTriggerArgs(Arrays.asList(String.format("http://%s:%d/trigger",clientContainerInfo.getManagerHost(), clientContainerInfo.getManagerPort())));
        return inboundConnectionWCTA;
    }

    private Function<State, Integer> getOpenSSLClientTriggerScript(){

        Function<State, Integer> triggerScript = (State state) -> {
            InboundConnection inboundConnection = state.getConfig().getDefaultServerConnection();
            if(!(inboundConnection instanceof InboundConnectionWithCustomTriggerArgs)){
                LOGGER.error("InboundConnection has no args.");
            }
            InboundConnectionWithCustomTriggerArgs inboundConnectionWCTA =
                    (InboundConnectionWithCustomTriggerArgs) inboundConnection;
            List<String> triggerCommand = Stream.concat(TRIGGER_COMMAND_PREFIX.stream(), inboundConnectionWCTA.getTriggerArgs().stream())
                    .collect(Collectors.toList());
            try {
                ProcessBuilder processBuilder = new ProcessBuilder(triggerCommand);
                Process p = processBuilder.start();
                return 0;
            } catch (IOException ex) {
                LOGGER.error(ex);
                return 1;
            }
        };

        return triggerScript;
    }

    private void disableInfoAndWarnLogging(Logger logger){
        org.apache.logging.log4j.core.Logger coreLogger = (org.apache.logging.log4j.core.Logger) logger;
        final LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        final Configuration config = ctx.getConfiguration();

        config.addLoggerFilter(coreLogger, noErrorAndWarningsFilter);
    }

}

