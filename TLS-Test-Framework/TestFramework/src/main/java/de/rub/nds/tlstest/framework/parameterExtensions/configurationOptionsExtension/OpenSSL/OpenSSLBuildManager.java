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
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.transport.DockerHttpClient;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector.OpenSSLConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
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

    private ConfigurationOptionsConfig configOptionsConfig;

    private Map<String, TestSiteReport> dockerTagToSiteReport;
    private Map<String, DockerContainerInfo> dockerTagToContainerInfo;
    private Map<String, Integer> dockerTagToAccessCount;
    private Map<String, Integer> dockerTagToCurrentUseCount;

    private DockerClient dockerClient;
    private OpenSSLDockerHelper dockerHelper;
    private Set<String> existingDockerImageNameWithTags;
    private Path dockerfileMinPath;
    private String maximalFeatureContainerDockerTag;

    private OpenSSLConfigOptionsResultsCollector resultsCollector;

    private Set<Integer> usedPorts;

    private final String CCACHE_VOLUME_NAME = "ccache-cache";
    private final List<String> TRIGGER_COMMAND_PREFIX = Arrays.asList("curl");
    private final String TLS_SERVER_HOST;


    public OpenSSLBuildManager(ConfigurationOptionsConfig configurationOptionsConfig){
        configOptionsConfig = configurationOptionsConfig;
        usedPorts = new HashSet<>();
        dockerTagToSiteReport = new HashMap<>();
        dockerTagToContainerInfo = new HashMap<>();
        dockerTagToAccessCount = new HashMap<>();
        dockerTagToCurrentUseCount = new HashMap<>();
        TLS_SERVER_HOST = configurationOptionsConfig.getDockerClientDestinationHostName();
    }

    @Override
    public void init(){
        DefaultDockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder().build();

        DockerHttpClient httpClient = (new com.github.dockerjava.jaxrs.JerseyDockerHttpClient.Builder()).dockerHost(config.getDockerHost()).sslConfig(config.getSSLConfig()).build();

        dockerClient = DockerClientBuilder
                .getInstance(config)
                .withDockerHttpClient(httpClient)
                .build();

        dockerHelper = new OpenSSLDockerHelper(dockerClient, configOptionsConfig.isWithCoverage());

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
        String factoryImageNameWithTag = dockerHelper.getFactoryImageNameAndTag(openSSLBranchName);
        if(!dockerNameWithTagExists(factoryImageNameWithTag)){
            dockerHelper.createFactoryImage(pathToFactoryDockerfile, openSSLBranchName);
        }

        dockerfileMinPath = pathToMinDockerfile;

        configOpenSSLDefaultConnection();
    }

    /**
     * Configures the config using the passed optionSet to delegate the connection to an implementation built with
     * the respective option set. Calling this function blocks the respective docker container, so it can't be paused.
     * To unblock it the onTestFinished function is called at the end of each test.
     *
     * @param config - the specified Config
     * @param context - the test context
     * @param optionSet - the set of configurationOptionDerivationParameters that contain selected values.
     * @return
     */
    @Override
    public synchronized TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet) {
        String dockerTag = getDockerTagFromOptionSet(optionSet);
        startContainerUsage(dockerTag);
        String buildTag =  provideOpenSSLImplementation(optionSet);
        DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(buildTag);
        TestSiteReport report = getSiteReport(buildTag);

        // Configure the port in the config
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
            DockerServerContainerInfo serverContainerInfo = (DockerServerContainerInfo) containerInfo;
            OutboundConnection connection = new OutboundConnection(serverContainerInfo.getTlsServerPort(), configOptionsConfig.getDockerHostName());
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

    /**
     * Starts a docker container with the given options. Calling this method increases the use count for the respective
     * docker tag by one.
     *
     * @param optionSet - the options set to use
     * @returns the dockerTag for the created implementation. The tag can be used to find the created container and the TestSiteReport.
     */
    private synchronized String provideOpenSSLImplementation(Set<ConfigurationOptionDerivationParameter> optionSet){
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        String dockerTag = dockerHelper.computeDockerTag(cliOptions, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsVersionName());
        String dockerNameWithTag = dockerHelper.getOpenSSLBuildImageNameAndTag(dockerTag);
        DockerContainerInfo providedContainer;

        // Case: A docker container already exists
        if(dockerTagToContainerInfo.containsKey(dockerTag)){
            providedContainer = dockerTagToContainerInfo.get(dockerTag);
            if(providedContainer.getContainerState() == DockerContainerState.NOT_RUNNING) {
                dockerHelper.startContainer(providedContainer);
            }
            else if(providedContainer.getContainerState() == DockerContainerState.PAUSED){
                dockerHelper.unpauseContainer(providedContainer);
            }
        }
        // Case: A new container has to be created
        else{
            // SubCase: The image for the container does not already exists
            if(!dockerNameWithTagExists(dockerNameWithTag)){
                long timer = System.currentTimeMillis();
                dockerHelper.buildOpenSSLImageWithFactory(cliOptions, dockerTag, dockerfileMinPath, configOptionsConfig.getTlsVersionName(), resultsCollector);
                resultsCollector.logNewOpenSSLBuildCreated(optionSet, dockerTag, System.currentTimeMillis() - timer);
                existingDockerImageNameWithTags.add(dockerNameWithTag);
            }

            if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
                providedContainer = dockerHelper.createDockerClient(dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort(), TLS_SERVER_HOST, TestContext.getInstance().getConfig().getTestClientDelegate().getPort());
            }
            else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
                providedContainer = dockerHelper.createDockerServer(dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort(), occupyNextPort());
            }
            else{
                throw new IllegalStateException("TestEndpointMode is invalid.");
            }

            dockerHelper.startContainer(providedContainer);
            resultsCollector.logOpenSSLContainer(providedContainer);
            dockerTagToContainerInfo.put(dockerTag, providedContainer);
            dockerTagToAccessCount.put(dockerTag, 0);
        }



        resultsCollector.logBuildAccess(optionSet, dockerTag);
        dockerTagToAccessCount.put(dockerTag, dockerTagToAccessCount.get(dockerTag)+1);
        return dockerTag;
    }

    private Set<ConfigurationOptionDerivationParameter> getMaxFeatureOptionSet(){
        List<DerivationType> derivationTypes = ConfigurationOptionsDerivationManager.getInstance().getDerivationsOfModel(ModelType.GENERIC);
        Set<ConfigurationOptionDerivationParameter> optionSet = new HashSet<>();
        for (DerivationType type : derivationTypes) {
            ConfigurationOptionDerivationParameter configOptionDerivation
                    = (ConfigurationOptionDerivationParameter) ConfigurationOptionsDerivationManager.getInstance().getDerivationParameterInstance(type);
            configOptionDerivation.setSelectedValue(configOptionDerivation.getMaxFeatureValue());
            optionSet.add(configOptionDerivation);
        }
        return optionSet;
    }

    @Override
    public synchronized void onTestFinished(Set<ConfigurationOptionDerivationParameter> optionSet){
        String dockerTag = getDockerTagFromOptionSet(optionSet);
        endContainerUsage(dockerTag);
    }


    /* === Site Report Management === */

    public synchronized TestSiteReport getMaximalFeatureSiteReport(){
        if(maximalFeatureContainerDockerTag == null) {
            Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
            maximalFeatureContainerDockerTag = provideOpenSSLImplementation(optionSet);
        }
        TestSiteReport report = getSiteReport(maximalFeatureContainerDockerTag);
        return report;
    }

    private TestSiteReport getSiteReport(String dockerTag){
        if(dockerTagToSiteReport.containsKey(dockerTag)){
            return dockerTagToSiteReport.get(dockerTag);
        }
        else{
            TestSiteReport report = createSiteReport(dockerTag);
            dockerTagToSiteReport.put(dockerTag, report);
            return report;
        }
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
        startContainerUsage(dockerTag);
        DockerServerContainerInfo serverContainerInfo = (DockerServerContainerInfo) dockerTagToContainerInfo.get(dockerTag);
        TestSiteReport report = TestSiteReportFactory.createServerSiteReport(configOptionsConfig.getDockerHostName(), serverContainerInfo.getTlsServerPort(), configOptionsConfig.isSiteReportConsoleLogDisabled());
        endContainerUsage(dockerTag);

        return report;
    }

    public synchronized TestSiteReport createClientSiteReport(String dockerTag){
        startContainerUsage(dockerTag);
        DockerClientContainerInfo clientContainerInfo = (DockerClientContainerInfo) dockerTagToContainerInfo.get(dockerTag);

        Config config = TestContext.getInstance().getConfig().createConfig();
        InboundConnectionWithCustomTriggerArgs ibConnectionWCTA = createTriggerConnectionForContainer(clientContainerInfo, config);
        TestSiteReport report =  TestSiteReportFactory.createClientSiteReport(TestContext.getInstance().getConfig(), ibConnectionWCTA, configOptionsConfig.isSiteReportConsoleLogDisabled());
        endContainerUsage(dockerTag);

        return report;
    }

    /* === Pause/Unpause Logic === */

    private synchronized void startContainerUsage(String dockerTag){
        if(!dockerTagToCurrentUseCount.containsKey(dockerTag)){
            dockerTagToCurrentUseCount.put(dockerTag, 0);
        }
        if(dockerTagToContainerInfo.containsKey(dockerTag)){
            DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(dockerTag);
            if(containerInfo.getContainerState() == DockerContainerState.PAUSED){
                dockerHelper.unpauseContainer(containerInfo);
            }
        }


        Integer currentInUseCount = dockerTagToCurrentUseCount.get(dockerTag);
        currentInUseCount += 1;
        dockerTagToCurrentUseCount.put(dockerTag, currentInUseCount);

        pauseRarelyUsedContainers();
    }

    private synchronized void endContainerUsage(String dockerTag){
        Integer currentInUseCount = dockerTagToCurrentUseCount.get(dockerTag);
        currentInUseCount -= 1;

        if(currentInUseCount < 0){
            LOGGER.error(String.format("Use count of docker tag '%s' is smaller than 0. This should not happen.", dockerTag));
            currentInUseCount = 0;
        }

        dockerTagToCurrentUseCount.put(dockerTag, currentInUseCount);
    }

    private synchronized boolean isContainerInUse(String dockerTag){
        if(!dockerTagToCurrentUseCount.containsKey(dockerTag)){
            return false;
        }
        else{
            return (dockerTagToCurrentUseCount.get(dockerTag) > 0);
        }
    }

    private synchronized void pauseRarelyUsedContainers(){
        // Count running containers
        Set<String> runningUnusedContainerDockerTags = new HashSet<>();
        int currentlyUsedCount = 0;
        for (Map.Entry<String, DockerContainerInfo> entry : dockerTagToContainerInfo.entrySet()) {
            // Currently used containers are ignored
            if(isContainerInUse(entry.getKey())){
                currentlyUsedCount += 1;
                continue;
            }

            if(entry.getValue().getContainerState() == DockerContainerState.RUNNING){
                runningUnusedContainerDockerTags.add(entry.getKey());
            }
        }
        if(runningUnusedContainerDockerTags.size() <= configOptionsConfig.getMaxRunningContainers() - currentlyUsedCount){
            return;
        }

        List<Map.Entry<String, Integer>> runningContainersAccessCounts = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : dockerTagToAccessCount.entrySet()) {
            if(runningUnusedContainerDockerTags.contains(entry.getKey())){
                runningContainersAccessCounts.add(entry);
            }
        }

        // Pause the running containers with the lowest access count
        runningContainersAccessCounts.sort(Map.Entry.comparingByValue());
        int freeSlotsCount =Math.max(0,configOptionsConfig.getMaxRunningContainers() - currentlyUsedCount);
        for(int idx = 0; idx < runningContainersAccessCounts.size() - freeSlotsCount; idx++){
            DockerContainerInfo containerToPause = dockerTagToContainerInfo.get(runningContainersAccessCounts.get(idx).getKey());
            dockerHelper.pauseContainer(containerToPause);
        }
    }

    /* === Port Logic === */

    private Integer occupyNextPort(){
        PortRange portRange = configOptionsConfig.getDockerPortRange();
        Integer port;
        boolean portFound = false;
        for(port =  portRange.getMinPort(); port <= portRange.getMaxPort(); port++){
            if(usedPorts.contains(port)){
                continue;
            }
            else{
                if(isPortAvailable(port)){
                    portFound = true;
                    break;
                }
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

    /**
     * Checks if a port is still available on the system. (Stackoverflow code)
     *
     * @param port - the port to check
     * @returns true iff the port is still available
     */
    private static boolean isPortAvailable(int port) {

        ServerSocket ss = null;
        DatagramSocket ds = null;
        try {
            ss = new ServerSocket(port);
            ss.setReuseAddress(true);
            ds = new DatagramSocket(port);
            ds.setReuseAddress(true);
            return true;
        } catch (IOException e) {
        } finally {
            if (ds != null) {
                ds.close();
            }

            if (ss != null) {
                try {
                    ss.close();
                } catch (IOException e) {
                    /* should not be thrown */
                }
            }
        }

        return false;
    }

    /* === Init Utils === */

    /**
     * The input parameter model for some test cases may exclude every configuration options. In this case we cannot
     * provide a build, since the respective method is never called. If this happens, the connection is delegated to
     * a build with the maximal feature amount. This function overrides the default delegates, so that the default
     * connection is delegated to these maximal feature builds.
     */
    private void configOpenSSLDefaultConnection(){
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
            TestContext.getInstance().getConfig().getTestClientDelegate().setTriggerScript(getOpenSSLClientTriggerScript());
        }
        else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
            if(maximalFeatureContainerDockerTag == null) {
                Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
                maximalFeatureContainerDockerTag = provideOpenSSLImplementation(optionSet);
            }

            DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
            if(!(containerInfo instanceof DockerServerContainerInfo)){
                throw new IllegalStateException("Maximal-Feature docker container is not a server container in server mode. This should never happen.");
            }
            DockerServerContainerInfo serverContainerInfo = (DockerServerContainerInfo) containerInfo;
            String hostWithPort = String.format("%s:%d", configOptionsConfig.getDockerHostName(), serverContainerInfo.getTlsServerPort());
            TestContext.getInstance().getConfig().getTestServerDelegate().setHost(hostWithPort);
        }
        else{
            throw new IllegalStateException("TestEndpointMode is invalid.");
        }
        // Used to override host and port in the next execution of get createConfig
        TestContext.getInstance().getConfig().clearConfigCache();

        // Assure that the max implementation is never paused
        startContainerUsage(maximalFeatureContainerDockerTag);

    }

    private InboundConnectionWithCustomTriggerArgs createTriggerConnectionForContainer(DockerClientContainerInfo clientContainerInfo, Config config){
        InboundConnectionWithCustomTriggerArgs inboundConnectionWCTA = new InboundConnectionWithCustomTriggerArgs(config.getDefaultServerConnection());
        inboundConnectionWCTA.setTriggerArgs(Arrays.asList(String.format("http://%s:%d/trigger",clientContainerInfo.getDockerHost(), clientContainerInfo.getManagerPort())));
        return inboundConnectionWCTA;
    }

    private Function<State, Integer> getOpenSSLClientTriggerScript(){
        if(TestContext.getInstance().getConfig().getTestEndpointMode() != TestEndpointType.CLIENT){
            throw new IllegalStateException("Function must not be called in Server Mode!");
        }


        if(maximalFeatureContainerDockerTag == null) {
            Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
            maximalFeatureContainerDockerTag = provideOpenSSLImplementation(optionSet);
        }
        DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
        if(!(containerInfo instanceof DockerClientContainerInfo)){
            throw new IllegalStateException("Maximal-Feature docker container is not a client container in client mode. This should never happen.");
        }
        DockerClientContainerInfo clientContainerInfo = (DockerClientContainerInfo) containerInfo;


        final String MAX_FEATURE_CONTAINER_TRIGGER_ADDRESS
                = String.format("http://%s:%d/trigger", clientContainerInfo.getDockerHost(), clientContainerInfo.getManagerPort());

        Function<State, Integer> triggerScript = (State state) -> {
            InboundConnection inboundConnection = state.getConfig().getDefaultServerConnection();
            // Build the process
            List<String> triggerCommand;
            if(!(inboundConnection instanceof InboundConnectionWithCustomTriggerArgs)){
                LOGGER.warn("InboundConnection has no args. Maximal-Feature container is used.");
                triggerCommand = Stream.concat(TRIGGER_COMMAND_PREFIX.stream(), Stream.of(MAX_FEATURE_CONTAINER_TRIGGER_ADDRESS))
                        .collect(Collectors.toList());
            }
            else {
                InboundConnectionWithCustomTriggerArgs inboundConnectionWCTA =
                        (InboundConnectionWithCustomTriggerArgs) inboundConnection;
                triggerCommand = Stream.concat(TRIGGER_COMMAND_PREFIX.stream(), inboundConnectionWCTA.getTriggerArgs().stream())
                        .collect(Collectors.toList());
            }
            // Run the process
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

    /* === Shutdown Logic === */

    @Override
    public synchronized void onShutdown(){
        resultsCollector.finalizeResults();

        Set<String> runningContainers = new HashSet<>();
        List<Set<String>> pausedContainersSubsets = new LinkedList<>();
        pausedContainersSubsets.add(new HashSet<>());
        int currentPausedContainersSetsIdx = 0;
        int currentSubsetSize = 0;
        for(Map.Entry<String, DockerContainerInfo> entry : dockerTagToContainerInfo.entrySet()){
            if (entry.getValue().getContainerState() == DockerContainerState.RUNNING) {
                runningContainers.add(entry.getKey());
            }
            // Split the paused containers in subsets of MAX_RUNNING_DOCKER_CONTAINERS containers which are
            // shutdown simultaneously
            else if(entry.getValue().getContainerState() == DockerContainerState.PAUSED){
                if(currentSubsetSize >= configOptionsConfig.getMaxRunningContainers()){
                    pausedContainersSubsets.add(new HashSet<>());
                    currentPausedContainersSetsIdx += 1;
                    currentSubsetSize = 0;
                }
                pausedContainersSubsets.get(currentPausedContainersSetsIdx).add(entry.getKey());
                currentSubsetSize += 1;

            }
        }

        // Shutdown running containers first to free resources
        LOGGER.info("Shutdown and clear all containers. This may take a while...");
        shutdownContainerSet(runningContainers);

        // Shutdown the remaining (paused) containers
        for(Set<String> pausedSubset : pausedContainersSubsets){
            shutdownContainerSet(pausedSubset);
        }

        // Pause all containers
        for (Map.Entry<String, DockerContainerInfo> entry : dockerTagToContainerInfo.entrySet()) {
            if (entry.getValue().getContainerState() == DockerContainerState.RUNNING) {
                dockerHelper.unpauseContainer(entry.getValue());
            }
        }

        // Trigger the shutdown process of all created containers
        LOGGER.info("Shutdown and clear all containers...");
    }

    private synchronized void shutdownContainerSet(Set<String> dockerTagsToShutdown){
        for (String entry : dockerTagsToShutdown) {
            DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(entry);
            if(containerInfo == null){
                continue;
            }
            if(containerInfo.getContainerState() == DockerContainerState.NOT_RUNNING){
                continue;
            }

            if(containerInfo.getContainerState() == DockerContainerState.PAUSED){
                dockerHelper.unpauseContainer(containerInfo);
            }

            List<String> shutdownHttpRequest;
            if(containerInfo instanceof DockerClientContainerInfo){
                DockerClientContainerInfo clientContainerInfo = (DockerClientContainerInfo) containerInfo;
                shutdownHttpRequest = Arrays.asList(String.format("http://%s:%d/shutdown", clientContainerInfo.getDockerHost(), clientContainerInfo.getManagerPort()));
            }
            else if(containerInfo instanceof DockerServerContainerInfo){
                DockerServerContainerInfo serverContainerInfo = (DockerServerContainerInfo) containerInfo;
                shutdownHttpRequest = Arrays.asList(String.format("http://%s:%d/shutdown", serverContainerInfo.getDockerHost(), serverContainerInfo.getManagerPort()));
            }
            else {
                // Should not happen
                dockerHelper.stopContainer(containerInfo);
                continue;
            }

            List<String> shutdownCommand = Stream.concat(TRIGGER_COMMAND_PREFIX.stream(), shutdownHttpRequest.stream())
                    .collect(Collectors.toList());

            try {
                ProcessBuilder processBuilder = new ProcessBuilder(shutdownCommand);
                Process p = processBuilder.start();
            } catch (IOException ex) {
                LOGGER.error(ex);
            }
        }

        // Wait for containers to shutdown properly and remove them afterwards
        for (String entry : dockerTagsToShutdown) {
            DockerContainerInfo containerInfo = dockerTagToContainerInfo.get(entry);
            // Wait for container to finish
            boolean isRunning;
            do{
                try {
                    InspectContainerResponse containerResp = dockerClient.inspectContainerCmd(containerInfo.getContainerId()).exec();
                    isRunning = containerResp.getState().getRunning();
                    if(isRunning){
                        Thread.sleep(1000);
                    }
                }
                catch(InterruptedException | NullPointerException e){
                    e.printStackTrace();
                    isRunning = false;
                }
            }
            while(isRunning);

            // Remove the container afterwards
            dockerHelper.removeContainer(containerInfo);
        }

    }

    /* === Misc === */

    private String getDockerTagFromOptionSet(Set<ConfigurationOptionDerivationParameter> optionSet){
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        String dockerTag = dockerHelper.computeDockerTag(cliOptions, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsVersionName());
        return dockerTag;
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
        else if(translation instanceof SingleValueOptionTranslation){
            SingleValueOptionTranslation singleValueTranslation = (SingleValueOptionTranslation) translation;
            if(value.isFlag()){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation has a value, but the ConfigurationOptionValue is a flag. Value can't be translated.");
            }
            List<String> optionValues = value.getOptionValues();
            if(optionValues.size() != 1){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation has a single value, but the ConfigurationOptionValue is not a single value. Value can't be translated.");
            }
            String optionValue = optionValues.get(0);

            String translatedName = singleValueTranslation.getIdentifier();
            String translatedValue = singleValueTranslation.getValueTranslation(optionValue);

            return String.format("%s=%s", translatedName, translatedValue);
        }
        else{
            throw new UnsupportedOperationException(String.format("The OpenSSLBuildManager does not support translations '%s'.", translation.getClass()));
        }
    }

    private boolean dockerNameWithTagExists(String dockerTag){
        return existingDockerImageNameWithTags.contains(dockerTag);
    }

}

