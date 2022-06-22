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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ConfigurationOptionsBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ParallelExecutorWithTimeout;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.TestCOMultiClientDelegate;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigOptionValueTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.PortRange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.*;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;

/**
 * An abstract ConfigurationOptionsBuildManager that works with docker to create and manage builds. It uses a specific
 * DockerFactory for build creation. Each tls library build container runs an http server for management that can
 * be accessed using a separate port that is assigned to each container.
 *
 * Unused containers with the lowest usage are stopped and only reactivated if used again.
 */
public abstract class DockerBasedBuildManager extends ConfigurationOptionsBuildManager {
    private static final Logger LOGGER = LogManager.getLogger();

    protected DockerFactory dockerFactory;
    protected ConfigOptionsResultsCollector resultsCollector;
    protected ConfigurationOptionsConfig configOptionsConfig;
    protected Map<String, DockerTestContainer> dockerTagToContainerInfo;
    protected Map<String, Integer> dockerTagToAccessCount;
    protected Set<Integer> usedPorts;
    private String maximalFeatureContainerDockerTag;


    /**
     * Callable to create/get site reports.
     */
    public static class SiteReportCallback implements Callable<TestSiteReport> {
        DockerTestContainer container;
        private SiteReportCallback(DockerTestContainer container){
            this.container = container;
        }

        @Override
        public TestSiteReport call() {
            return container.getSiteReport();
        }
    }

    /**
     * Constructor. The DockerFactory passed decides which how specific builds are generated.
     *
     * @param configurationOptionsConfig The config parsed from the configuration options config file
     * @param dockerFactory The docker factory to used. Should be chosen by the subclass
     */
    public DockerBasedBuildManager(ConfigurationOptionsConfig configurationOptionsConfig, DockerFactory dockerFactory){
        this.dockerFactory = dockerFactory;
        this.configOptionsConfig = configurationOptionsConfig;
        dockerTagToContainerInfo = new HashMap<>();
        dockerTagToAccessCount = new HashMap<>();
        usedPorts = new HashSet<>();
    }

    @Override
    public synchronized void init(){
        this.dockerFactory.init();

        ParallelExecutor executor = new ParallelExecutorWithTimeout(TestContext.getInstance().getConfig().getParallelHandshakes(), 2, 600);
        TestContext.getInstance().setStateExecutor(executor);

        resultsCollector = new ConfigOptionsResultsCollector(Paths.get(TestContext.getInstance().getConfig().getOutputFolder()), configOptionsConfig, dockerFactory.getDockerClient());

        configDefaultConnection();
    }

    /**
     * Configures the config using the passed optionSet to delegate the connection to an implementation built with
     * the respective option set. Calling this function blocks the respective docker container, so it can't be paused.
     * To unblock it the onTestFinished function is called at the end of each test.
     *
     * @param config the specified Config
     * @param context the test context
     * @param optionSet the set of configurationOptionDerivationParameters that contain selected values.
     * @return the site report of the built for the passed option set
     */
    @Override
    public synchronized Callable<TestSiteReport> configureOptionSetAndReturnGetSiteReportCallable(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet) {
        String buildTag =  provideDockerContainer(optionSet);
        DockerTestContainer containerInfo = dockerTagToContainerInfo.get(buildTag);
        containerInfo.startUsage();
        stopRarelyUsedContainers();
        //TestSiteReport report = containerInfo.getSiteReport();
        Callable<TestSiteReport> siteReportCallback = new SiteReportCallback(containerInfo);

        // Configure the port in the config
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
            DockerServerTestContainer serverContainerInfo = (DockerServerTestContainer) containerInfo;
            OutboundConnection connection = new OutboundConnection(serverContainerInfo.getTlsServerPort(), configOptionsConfig.getDockerHostName());
            config.setDefaultClientConnection(connection);
        }
        else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
            DockerClientTestContainer clientContainerInfo = (DockerClientTestContainer) containerInfo;

            InboundConnection inboundConnection = createInboundConnectionForContainer(clientContainerInfo);
            config.setDefaultServerConnection(inboundConnection);
        }
        else{
            throw new IllegalStateException("TestEndpointMode is invalid.");
        }

        return siteReportCallback;
    }

    /**
     * Starts a docker container with the given options. Calling this method increases the use count for the respective
     * docker tag by one.
     *
     * @param optionSet - the options set to use
     * @return the dockerTag for the created implementation. The tag can be used to find the created container and the TestSiteReport.
     */
    protected synchronized String provideDockerContainer(Set<ConfigurationOptionDerivationParameter> optionSet){
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        String dockerTag = dockerFactory.computeDockerTag(cliOptions, configOptionsConfig.getTlsVersionName());
        String dockerNameWithTag = dockerFactory.getBuildImageNameAndTag(dockerTag);
        DockerTestContainer providedContainer;

        // Case: A docker container already exists
        if(dockerTagToContainerInfo.containsKey(dockerTag)){
            providedContainer = dockerTagToContainerInfo.get(dockerTag);
            runContainer(providedContainer);
        }
        // Case: A new container has to be created
        else{
            if(dockerFactory.buildFailedForTag(dockerTag)){
                throw new RuntimeException(String.format("Cannot create docker container for tag '%s'. Building has already failed.", dockerTag));
            }

            // SubCase: The image for the container does not already exists
            if(!dockerFactory.dockerNameWithTagExists(dockerNameWithTag)){
                LOGGER.info(String.format("Build new image with tag '%s'...", dockerTag));
                long timer = System.currentTimeMillis();
                boolean success = dockerFactory.buildTlsLibraryDockerImage(cliOptions, dockerTag, configOptionsConfig.getTlsVersionName(), resultsCollector);
                resultsCollector.logNewBuildCreated(optionSet, dockerTag, System.currentTimeMillis() - timer, success);
                if(!success){
                    throw new RuntimeException(String.format("Cannot create docker container for tag '%s'. Building failed.", dockerTag));
                }
            }

            if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
                DockerClientTestContainer container = dockerFactory.createDockerClient(dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort(), configOptionsConfig.getDockerClientDestinationHostName(), occupyNextPort());
                TestCOMultiClientDelegate delegate = (TestCOMultiClientDelegate)TestContext.getInstance().getConfig().getTestClientDelegate();
                delegate.registerNewConnection(container);
                providedContainer = container;
            }
            else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
                providedContainer = dockerFactory.createDockerServer(dockerTag, configOptionsConfig.getDockerHostName(), occupyNextPort(), occupyNextPort());
            }
            else{
                throw new IllegalStateException("TestEndpointMode is invalid.");
            }
            runContainer(providedContainer);

            //resultsCollector.logContainer(providedContainer);
            providedContainer.enableContainerLogging(resultsCollector, "ContainerLog", dockerTag);
            dockerTagToContainerInfo.put(dockerTag, providedContainer);
            dockerTagToAccessCount.put(dockerTag, 0);
        }

        resultsCollector.logBuildAccess(optionSet, dockerTag);
        dockerTagToAccessCount.put(dockerTag, dockerTagToAccessCount.get(dockerTag)+1);
        return dockerTag;
    }

    /**
     * Return the option set that leads to a build supporting the most features.
     *
     * @return the option set
     */
    protected Set<ConfigurationOptionDerivationParameter> getMaxFeatureOptionSet(){
        List<ConfigOptionDerivationType> derivationTypes = ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes();
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
        if(dockerTagToContainerInfo.containsKey(dockerTag)){
            dockerTagToContainerInfo.get(dockerTag).endUsage();
        }
    }

    /* === Site Report Management === */
    @Override
    public synchronized TestSiteReport getMaximalFeatureSiteReport(){
        if(maximalFeatureContainerDockerTag == null) {
            Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
            maximalFeatureContainerDockerTag = provideDockerContainer(optionSet);
        }
        DockerTestContainer container = dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
        return container.getSiteReport();
    }

    /**
     * Stops the most rarely used, currently unused containers if the current container count surpasses the maximal
     * amount defined in the ConfigOptionsConfig.
     */
    protected synchronized void stopRarelyUsedContainers(){
        // Count running containers
        Set<String> runningUnusedContainerDockerTags = new HashSet<>();
        int currentlyUsedCount = 0;
        for (Map.Entry<String, DockerTestContainer> entry : dockerTagToContainerInfo.entrySet()) {
            // Currently used containers are ignored
            if(entry.getValue().isInUse()){
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

        // Stop the running containers with the lowest access count
        runningContainersAccessCounts.sort(Map.Entry.comparingByValue());
        int freeSlotsCount =Math.max(0,configOptionsConfig.getMaxRunningContainers() - currentlyUsedCount);
        for(int idx = 0; idx < runningContainersAccessCounts.size() - freeSlotsCount; idx++){
            DockerTestContainer containerToStop = dockerTagToContainerInfo.get(runningContainersAccessCounts.get(idx).getKey());
            containerToStop.stop();
        }
    }

    /* === Port Logic === */

    /**
     * Get a new free port within the port range defined in the configOptionsConfig file. Ports already used by other
     * processes are skipped.
     * @return the occupied port
     */
    protected synchronized Integer occupyNextPort(){
        PortRange portRange = configOptionsConfig.getDockerPortRange();
        Integer port;
        boolean portFound = false;
        for(port =  portRange.getMinPort(); port <= portRange.getMaxPort(); port++){
            if(!usedPorts.contains(port)){
                if(DockerBasedBuildManager.isPortAvailable(port)){
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

    /**
     * Free a port that was occupied by occupyNextPort() so it can be occupied again. Currently unused.
     *
     * @param port - The port to free.
     */
    @SuppressWarnings("unused")
    protected void freeOccupiedPort(Integer port){
        usedPorts.remove(port);
    }

    /**
     * Checks if a port is still available on the system. (Stackoverflow code)
     *
     * @param port - the port to check
     * @return true iff the port is still available
     */
    protected static boolean isPortAvailable(int port) {

        ServerSocket ss = null;
        DatagramSocket ds = null;
        try {
            ss = new ServerSocket(port);
            ss.setReuseAddress(true);
            ds = new DatagramSocket(port);
            ds.setReuseAddress(true);
            return true;
        } catch (IOException ignored) {
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

    /**
     * The input parameter model for some test cases may exclude every configuration options. In this case we cannot
     * provide a build, since the respective method is never called. If this happens, the connection is delegated to
     * a build with the maximal feature amount. This function overrides the default delegates, so that the default
     * connection is delegated to these maximal feature builds.
     */
    private synchronized void configDefaultConnection(){

        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT){
            TestCOMultiClientDelegate delegate = new TestCOMultiClientDelegate();
            TestContext.getInstance().getConfig().setTestClientDelegate(delegate);

            if(maximalFeatureContainerDockerTag == null) {
                Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
                maximalFeatureContainerDockerTag = provideDockerContainer(optionSet);
            }

            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
            if(!(containerInfo instanceof DockerClientTestContainer)){
                throw new IllegalStateException("Maximal-Feature docker container is not a client container in client mode. This should never happen.");
            }
            DockerClientTestContainer clientContainerInfo = (DockerClientTestContainer) containerInfo;
            delegate.configureDefaultInboundPort(clientContainerInfo.getInboundConnectionPort());

        }
        else if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER){
            if(maximalFeatureContainerDockerTag == null) {
                Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
                maximalFeatureContainerDockerTag = provideDockerContainer(optionSet);
            }

            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
            if(!(containerInfo instanceof DockerServerTestContainer)){
                throw new IllegalStateException("Maximal-Feature docker container is not a server container in server mode. This should never happen.");
            }
            DockerServerTestContainer serverContainerInfo = (DockerServerTestContainer) containerInfo;
            String hostWithPort = String.format("%s:%d", configOptionsConfig.getDockerHostName(), serverContainerInfo.getTlsServerPort());
            TestContext.getInstance().getConfig().getTestServerDelegate().setHost(hostWithPort);
        }
        else{
            throw new IllegalStateException("TestEndpointMode is invalid.");
        }
        // Used to override host and port in the next execution of get createConfig
        TestContext.getInstance().getConfig().clearConfigCache();

        // Assure that the max implementation is never paused
        dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag).startUsage();

    }

    private InboundConnection createInboundConnectionForContainer(DockerClientTestContainer clientContainerInfo){
        return new InboundConnection(clientContainerInfo.getInboundConnectionPort(), configOptionsConfig.getDockerClientDestinationHostName());
    }

    /**
     * Finalizes the result logs and properly shutdown all created containers. The amount of containers shutdown
     * simultaneously is defined in the config options config
     */
    @Override
    public synchronized void onShutdown(){
        resultsCollector.finalizeResults();

        // Stop all running containers
        for(Map.Entry<String, DockerTestContainer> entry : dockerTagToContainerInfo.entrySet()){
            if (entry.getValue().getContainerState() == DockerContainerState.RUNNING) {
                entry.getValue().stop();
            }
        }

        // Devide all containers in subsets of <maxRunningContainer> containers for simultaneous shutdown.
        List<Set<String>> containersSubsets = new LinkedList<>();
        containersSubsets.add(new HashSet<>());
        int containerSetsIdx = 0;
        int currentSubsetSize = 0;
        for(Map.Entry<String, DockerTestContainer> entry : dockerTagToContainerInfo.entrySet()){
            if(currentSubsetSize >= configOptionsConfig.getMaxRunningContainerShutdowns()){
                containersSubsets.add(new HashSet<>());
                containerSetsIdx += 1;
                currentSubsetSize = 0;
            }
            containersSubsets.get(containerSetsIdx).add(entry.getKey());
            currentSubsetSize += 1;
        }

        LOGGER.info("Shutdown and clear all containers. This may take a while...");
        // Shutdown all containers
        for(Set<String> notRunningSubset : containersSubsets){
            shutdownContainerSet(notRunningSubset);
        }
    }

    /**
     * Shutdown a set of docker containers. The amount of containers shutdown
     * simultaneously is defined in the config options config
     *
     * @param dockerTagsToShutdown - The tags of the containers to shutdown
     */
    protected synchronized void shutdownContainerSet(Set<String> dockerTagsToShutdown){
        Set<String> failedShutdownTags = new HashSet<>();
        // Start all containers that have to be shutdown
        for (String entry : dockerTagsToShutdown) {
            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(entry);
            if (containerInfo == null) {
                continue;
            }
            if (containerInfo.getContainerState() == DockerContainerState.INVALID){
                continue;
            }
            runContainer(containerInfo);
        }
        // Little delay to give containers time to start properly
        try {
            Thread.sleep(800);
        }
        catch(InterruptedException e){
            e.printStackTrace();
        }


        for (String entry : dockerTagsToShutdown) {
            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(entry);
            if(containerInfo == null){
                continue;
            }
            if (containerInfo.getContainerState() == DockerContainerState.INVALID){
                continue;
            }
            runContainer(containerInfo);

            try {
                containerInfo.sendHttpRequestToManager("shutdown");
            }
            catch(RuntimeException ex){
                ex.printStackTrace();
                failedShutdownTags.add(entry);
            }
        }

        // Wait for containers to shutdown properly and remove them afterwards
        for (String entry : dockerTagsToShutdown) {
            if(failedShutdownTags.contains(entry)){
                continue;
            }


            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(entry);
            if (containerInfo.getContainerState() == DockerContainerState.INVALID){
                continue;
            }
            // Wait for container to finish
            try{
                containerInfo.waitForState(DockerContainerState.NOT_RUNNING, 600000); // 10 min
            }
            catch(TimeoutException e){
                LOGGER.error(String.format("Cannot properly shutdown docker container with tag '%s'.", containerInfo.getDockerTag()));
            }

            // Remove the container afterwards
            containerInfo.remove();
        }

    }

    /* === Misc === */

    /**
     * Computes the dockerTag that is assigned to a specific optionSet (which also depends on the library version)
     *
     * @param optionSet - the option set to create the docker tag for
     * @return the resulting docker tag
     */
    protected String getDockerTagFromOptionSet(Set<ConfigurationOptionDerivationParameter> optionSet){
        List<String> cliOptions = createConfigOptionCliList(optionSet);
        return dockerFactory.computeDockerTag(cliOptions, configOptionsConfig.getTlsVersionName());
    }

    /**
     * Creates the commandline arguments necessary for the building the passed option set (using the library specific translation).
     * The resulting list is sorted alphabetically so it is deterministic.
     *
     *
     * It is assumed that options are defined in any order in a single command line command. (Must be overridden by subclasses otherwise).
     *
     * @param optionSet - the set of configuration options.
     * @return the sorted list of command line options
     */
    protected List<String> createConfigOptionCliList(Set<ConfigurationOptionDerivationParameter> optionSet){
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

    /**
     * Makes a container running. If it is paused it will be unpaused. If its not running it will be started.
     * It waits for the running state.
     *
     * @param container - The container to make running.
     */
    protected synchronized void runContainer(DockerTestContainer container){
        try {
            if (container.getContainerState() == DockerContainerState.NOT_RUNNING) {
                container.startAndWait();
            } else if (container.getContainerState() == DockerContainerState.PAUSED) {
                container.unpauseAndWait();
            }
            else if(container.getContainerState() == DockerContainerState.INVALID){
                throw new IllegalStateException(String.format("Cannot run container in state %s.", DockerContainerState.INVALID));
            }
        }
        catch(TimeoutException e){
            e.printStackTrace();
            throw new RuntimeException(String.format("Cannot start/unpause container with tag '%s'.", container.getDockerTag()));
        }
    }
}
