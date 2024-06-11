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

import com.beust.jcommander.Strings;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.anvilcore.model.parameter.ParameterType;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.build.DockerBuilder;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.execution.TestPreparator;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ParallelExecutorWithTimeout;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.TestCOMultiClientDelegate;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector.ConfigOptionsMetadataResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigOptionValueTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.FlagTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.PortRange;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.SingleValueOptionTranslation;
import java.io.IOException;
import java.net.*;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An abstract BuildManager that works with docker to create and manage builds. It uses a specific
 * DockerFactory for build creation. Each tls library build container runs an http server for
 * management that can be accessed using a separate port that is assigned to each container.
 *
 * <p>Unused containers with the lowest usage are stopped and only reactivated if used again.
 */
public class DockerBasedBuildManager {
    private static final Logger LOGGER = LogManager.getLogger();

    protected DockerFactory dockerFactory;
    protected ConfigOptionsMetadataResultsCollector resultsCollector;
    protected ConfigurationOptionsConfig configOptionsConfig;
    protected Map<String, DockerTestContainer> dockerTagToContainerInfo;
    protected Map<String, Integer> dockerTagToAccessCount;
    protected Set<Integer> usedPorts;
    protected TlsImplementationType dockerTlsImplementation;
    protected ConnectionRole libraryConnectionRole;
    protected String libraryVersion;
    private String maximalFeatureContainerDockerTag;

    /**
     * Callable to provide the container and obtain the feature extraction result during setup
     * phase.
     */
    public static class FeatureExtractionCallback implements Callable<FeatureExtractionResult> {
        private final DockerTestContainer testContainer;

        public FeatureExtractionCallback(DockerTestContainer testContainer) {
            this.testContainer = testContainer;
        }

        @Override
        public FeatureExtractionResult call() {
            return testContainer.getFeatureExtractionResult();
        }
    }

    /**
     * Constructor. The DockerFactory passed decides which how specific builds are generated.
     *
     * @param configurationOptionsConfig The config parsed from the configuration options config
     *     file
     * @param dockerFactory The docker factory to used. Should be chosen by the subclass
     */
    public DockerBasedBuildManager(
            ConfigurationOptionsConfig configurationOptionsConfig, DockerFactory dockerFactory) {
        this.dockerFactory = dockerFactory;
        this.configOptionsConfig = configurationOptionsConfig;
        dockerTagToContainerInfo = new HashMap<>();
        dockerTagToAccessCount = new HashMap<>();
        usedPorts = new HashSet<>();
        this.dockerTlsImplementation =
                TlsImplementationType.valueOf(configurationOptionsConfig.getTlsLibraryName());
        this.libraryVersion = configurationOptionsConfig.getTlsVersionName();
        if (TestContext.getInstance().getConfig().getTestEndpointMode()
                == TestEndpointType.CLIENT) {
            this.libraryConnectionRole = ConnectionRole.CLIENT;
        } else {
            this.libraryConnectionRole = ConnectionRole.SERVER;
        }
    }

    public synchronized void init() {
        this.dockerFactory.init();

        ParallelExecutor executor =
                new ParallelExecutorWithTimeout(
                        TestContext.getInstance()
                                .getConfig()
                                .getAnvilTestConfig()
                                .getParallelTestCases(),
                        1,
                        600);
        TestContext.getInstance().setStateExecutor(executor);

        setBuildConfigClientTestCallbacks(executor);

        resultsCollector =
                new ConfigOptionsMetadataResultsCollector(
                        Paths.get(
                                TestContext.getInstance()
                                        .getConfig()
                                        .getAnvilTestConfig()
                                        .getOutputFolder()),
                        configOptionsConfig,
                        dockerFactory.getDockerClient());

        configDefaultConnection();
    }

    /**
     * We first attempt to find an open port. This port is then passed to the client docker
     * container. To ensure that the port remains available to us, we immediately bind the socket to
     * the port. Hence, all connections must fetch their pre-initialized server socket to avoid
     * 'address alread in use' errors.
     *
     * @param executor The parallel executor to use
     */
    private void setBuildConfigClientTestCallbacks(ParallelExecutor executor) {
        if (TestContext.getInstance().getConfig().getTestEndpointMode()
                == TestEndpointType.CLIENT) {
            executor.setDefaultBeforeTransportPreInitCallback(
                    TestPreparator.getSocketManagementCallback());
            executor.setDefaultBeforeTransportInitCallback(
                    TestContext.getInstance()
                            .getConfig()
                            .getTestClientDelegate()
                            .getTriggerScript());
        }
    }

    /**
     * Configures the config using the passed optionSet to delegate the connection to an
     * implementation built with the respective option set. Calling this function blocks the
     * respective docker container, so it can't be paused. To unblock it the onTestFinished function
     * is called at the end of each test.
     *
     * @param config the specified Config
     * @param context the test context
     * @param optionSet the set of configurationOptionDerivationParameters that contain selected
     *     values. pr * @return the build tag used to reference the container
     */
    public String preparePeerConnection(
            Config config,
            TestContext context,
            Set<ConfigurationOptionDerivationParameter> optionSet) {
        String buildTag = provideDockerContainer(optionSet);
        synchronized (this) {
            DockerTestContainer dockerTestContainer = dockerTagToContainerInfo.get(buildTag);
            dockerTestContainer.startUsage();
            stopRarelyUsedContainers();

            // Configure the port in the config
            if (TestContext.getInstance().getConfig().getTestEndpointMode()
                    == TestEndpointType.SERVER) {
                DockerServerTestContainer serverContainerInfo =
                        (DockerServerTestContainer) dockerTestContainer;
                OutboundConnection connection =
                        new OutboundConnection(
                                serverContainerInfo.getTlsServerPort(),
                                configOptionsConfig.getDockerHostName());
                config.setDefaultClientConnection(connection);
            } else if (TestContext.getInstance().getConfig().getTestEndpointMode()
                    == TestEndpointType.CLIENT) {
                DockerClientTestContainer clientContainerInfo =
                        (DockerClientTestContainer) dockerTestContainer;

                InboundConnection inboundConnection =
                        createInboundConnectionForContainer(clientContainerInfo);
                config.setDefaultServerConnection(inboundConnection);
            } else {
                throw new IllegalStateException("TestEndpointMode is invalid.");
            }
        }
        return buildTag;
    }

    /**
     * Starts a docker container with the given options. Calling this method increases the use count
     * for the respective docker tag by one.
     *
     * @param optionSet - the options set to use
     * @return the dockerTag for the created implementation. The tag can be used to find the created
     *     container and the TestSiteReport.
     */
    protected String provideDockerContainer(Set<ConfigurationOptionDerivationParameter> optionSet) {
        String cliOptions = createConfigOptionCliString(optionSet);
        String dockerTag =
                DockerBuilder.getDefaultTag(
                        dockerTlsImplementation, libraryVersion, libraryConnectionRole, cliOptions);
        String dockerNameWithTag =
                DockerBuilder.getDefaultRepoAndTag(
                        dockerTlsImplementation, libraryVersion, libraryConnectionRole, cliOptions);
        DockerTestContainer providedContainer;
        // Case: A docker container already exists
        if (dockerTagToContainerInfo.containsKey(dockerTag)) {
            providedContainer = dockerTagToContainerInfo.get(dockerTag);
            runContainer(providedContainer);
        }
        // Case: A new container has to be created
        else {
            if (dockerFactory.buildFailedForRepoTag(dockerNameWithTag)) {
                throw new RuntimeException(
                        String.format(
                                "Cannot create docker container for tag '%s'. Building has already failed.",
                                dockerTag));
            }

            // SubCase: The image for the container does not already exists
            if (!dockerFactory.dockerNameWithTagExists(dockerNameWithTag)) {
                LOGGER.info(String.format("Build new image with tag '%s'...", dockerTag));
                long timer = System.currentTimeMillis();
                boolean success =
                        dockerFactory.buildTlsLibraryDockerImage(
                                dockerTlsImplementation,
                                libraryVersion,
                                libraryConnectionRole,
                                cliOptions);
                resultsCollector.logNewBuildCreated(
                        optionSet, dockerTag, System.currentTimeMillis() - timer, success);
                if (!success) {
                    throw new RuntimeException(
                            String.format(
                                    "Cannot create docker container for tag '%s'. Building failed.",
                                    dockerTag));
                }
            }
            synchronized (this) {
                if (TestContext.getInstance().getConfig().getTestEndpointMode()
                        == TestEndpointType.CLIENT) {
                    DockerClientTestContainer container =
                            dockerFactory.createDockerClient(
                                    dockerTag,
                                    configOptionsConfig.getDockerHostName(),
                                    occupyNextPort(),
                                    configOptionsConfig.getDockerClientDestinationHostName(),
                                    occupyNextPort());
                    TestCOMultiClientDelegate delegate =
                            (TestCOMultiClientDelegate)
                                    TestContext.getInstance().getConfig().getTestClientDelegate();
                    delegate.registerNewConnection(container);
                    providedContainer = container;
                } else if (TestContext.getInstance().getConfig().getTestEndpointMode()
                        == TestEndpointType.SERVER) {
                    providedContainer =
                            dockerFactory.createDockerServer(
                                    dockerTag,
                                    configOptionsConfig.getDockerHostName(),
                                    occupyNextPort(),
                                    occupyNextPort());
                } else {
                    throw new IllegalStateException("TestEndpointMode is invalid.");
                }
                runContainer(providedContainer);

                providedContainer.enableContainerLogging(
                        resultsCollector, "ContainerLog", dockerTag);
                dockerTagToContainerInfo.put(dockerTag, providedContainer);
                dockerTagToAccessCount.put(dockerTag, 0);
            }
        }
        synchronized (this) {
            resultsCollector.logBuildAccess(optionSet, dockerTag);
            dockerTagToAccessCount.put(dockerTag, dockerTagToAccessCount.get(dockerTag) + 1);
        }
        return dockerTag;
    }

    /**
     * Return the option set that leads to a build supporting the most features.
     *
     * @return the option set
     */
    protected Set<ConfigurationOptionDerivationParameter> getMaxFeatureOptionSet() {
        List<ConfigOptionParameterType> derivationTypes =
                ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes();
        Set<ConfigurationOptionDerivationParameter> optionSet = new HashSet<>();
        for (ParameterType type : derivationTypes) {
            ConfigurationOptionDerivationParameter configOptionDerivation =
                    (ConfigurationOptionDerivationParameter)
                            type.getInstance(ParameterScope.NO_SCOPE);
            optionSet.add(configOptionDerivation.getMaxFeatureValueParameter());
        }
        return optionSet;
    }

    public synchronized void onTestFinished(Set<ConfigurationOptionDerivationParameter> optionSet) {
        String dockerTag = getDockerTagFromOptionSet(optionSet);
        if (dockerTagToContainerInfo.containsKey(dockerTag)) {
            dockerTagToContainerInfo.get(dockerTag).endUsage();
        }
    }

    /* === Site Report Management === */
    public synchronized FeatureExtractionResult getMaximalFeatureExtractionResult() {
        if (maximalFeatureContainerDockerTag == null) {
            Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
            maximalFeatureContainerDockerTag = provideDockerContainer(optionSet);
        }
        DockerTestContainer container =
                dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
        return container.getFeatureExtractionResult();
    }

    /**
     * Stops the most rarely used, currently unused containers if the current container count
     * surpasses the maximal amount defined in the ConfigOptionsConfig.
     */
    protected synchronized void stopRarelyUsedContainers() {
        // Count running containers
        Set<String> runningUnusedContainerDockerTags = new HashSet<>();
        int currentlyUsedCount = 0;
        for (Map.Entry<String, DockerTestContainer> entry : dockerTagToContainerInfo.entrySet()) {
            // Currently used containers are ignored
            if (entry.getValue().isInUse()) {
                currentlyUsedCount += 1;
                continue;
            }

            if (entry.getValue().getContainerState() == DockerContainerState.RUNNING) {
                runningUnusedContainerDockerTags.add(entry.getKey());
            }
        }
        if (runningUnusedContainerDockerTags.size()
                <= configOptionsConfig.getMaxRunningContainers() - currentlyUsedCount) {
            return;
        }

        List<Map.Entry<String, Integer>> runningContainersAccessCounts = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : dockerTagToAccessCount.entrySet()) {
            if (runningUnusedContainerDockerTags.contains(entry.getKey())) {
                runningContainersAccessCounts.add(entry);
            }
        }

        // Stop the running containers with the lowest access count
        runningContainersAccessCounts.sort(Map.Entry.comparingByValue());
        int freeSlotsCount =
                Math.max(0, configOptionsConfig.getMaxRunningContainers() - currentlyUsedCount);
        for (int idx = 0; idx < runningContainersAccessCounts.size() - freeSlotsCount; idx++) {
            DockerTestContainer containerToStop =
                    dockerTagToContainerInfo.get(runningContainersAccessCounts.get(idx).getKey());
            containerToStop.stop();
        }
    }

    /* === Port Logic === */

    /**
     * Get a new free port within the port range defined in the configOptionsConfig file. Ports
     * already used by other processes are skipped.
     *
     * @return the occupied port
     */
    protected synchronized Integer occupyNextPort() {
        PortRange portRange = configOptionsConfig.getDockerPortRange();
        Integer port;
        boolean portFound = false;
        for (port = portRange.getMinPort(); port <= portRange.getMaxPort(); port++) {
            if (!usedPorts.contains(port)) {
                if (DockerBasedBuildManager.isPortAvailable(port)) {
                    portFound = true;
                    break;
                }
            }
        }
        if (!portFound) {
            throw new RuntimeException("Port range exhausted.");
        }

        usedPorts.add(port);
        return port;
    }

    /**
     * Free a port that was occupied by occupyNextPort() so it can be occupied again. Currently
     * unused.
     *
     * @param port - The port to free.
     */
    @SuppressWarnings("unused")
    protected void freeOccupiedPort(Integer port) {
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
        boolean bound = false;
        try {
            if (TestContext.getInstance().getConfig().isUseDTLS()) {
                ds = new DatagramSocket();
                ds.setReuseAddress(true);
                ds.bind(new InetSocketAddress(port));
                bound = true;
            } else {
                ss = new ServerSocket();
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress(port));
                bound = true;
            }
            return true;
        } catch (IOException ignored) {
        } finally {
            if (ds != null && bound) {
                ds.close();
            }

            if (ss != null && bound) {
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
     * The input parameter model for some test cases may exclude every configuration options. In
     * this case we cannot provide a build, since the respective method is never called. If this
     * happens, the connection is delegated to a build with the maximal feature amount. This
     * function overrides the default delegates, so that the default connection is delegated to
     * these maximal feature builds.
     */
    private synchronized void configDefaultConnection() {

        if (TestContext.getInstance().getConfig().getTestEndpointMode()
                == TestEndpointType.CLIENT) {
            TestCOMultiClientDelegate delegate = new TestCOMultiClientDelegate();
            TestContext.getInstance().getConfig().setTestClientDelegate(delegate);

            if (maximalFeatureContainerDockerTag == null) {
                Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
                maximalFeatureContainerDockerTag = provideDockerContainer(optionSet);
            }

            DockerTestContainer containerInfo =
                    dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
            if (!(containerInfo instanceof DockerClientTestContainer)) {
                throw new IllegalStateException(
                        "Maximal-Feature docker container is not a client container in client mode. This should never happen.");
            }
            DockerClientTestContainer clientContainerInfo =
                    (DockerClientTestContainer) containerInfo;
            delegate.configureDefaultInboundPort(clientContainerInfo.getInboundConnectionPort());

        } else if (TestContext.getInstance().getConfig().getTestEndpointMode()
                == TestEndpointType.SERVER) {
            if (maximalFeatureContainerDockerTag == null) {
                Set<ConfigurationOptionDerivationParameter> optionSet = getMaxFeatureOptionSet();
                maximalFeatureContainerDockerTag = provideDockerContainer(optionSet);
            }

            DockerTestContainer containerInfo =
                    dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag);
            if (!(containerInfo instanceof DockerServerTestContainer)) {
                throw new IllegalStateException(
                        "Maximal-Feature docker container is not a server container in server mode. This should never happen.");
            }
            DockerServerTestContainer serverContainerInfo =
                    (DockerServerTestContainer) containerInfo;
            String hostWithPort =
                    String.format(
                            "%s:%d",
                            configOptionsConfig.getDockerHostName(),
                            serverContainerInfo.getTlsServerPort());
            TestContext.getInstance().getConfig().getTestServerDelegate().setHost(hostWithPort);
        } else {
            throw new IllegalStateException("TestEndpointMode is invalid.");
        }

        // Assure that the max implementation is never paused
        dockerTagToContainerInfo.get(maximalFeatureContainerDockerTag).startUsage();
    }

    private InboundConnection createInboundConnectionForContainer(
            DockerClientTestContainer clientContainerInfo) {
        return new InboundConnection(
                clientContainerInfo.getInboundConnectionPort(),
                configOptionsConfig.getDockerClientDestinationHostName());
    }

    /**
     * Finalizes the result logs and properly shutdown all created containers. The amount of
     * containers shutdown simultaneously is defined in the config options config
     */
    public synchronized void onShutdown() {
        resultsCollector.finalizeResults();

        // Stop all running containers
        for (Map.Entry<String, DockerTestContainer> entry : dockerTagToContainerInfo.entrySet()) {
            if (entry.getValue().getContainerState() == DockerContainerState.RUNNING) {
                entry.getValue().stop();
            }
        }

        // Divide all containers in subsets of <maxRunningContainer> containers for simultaneous
        // shutdown.
        List<Set<String>> containersSubsets = new LinkedList<>();
        containersSubsets.add(new HashSet<>());
        int containerSetsIdx = 0;
        int currentSubsetSize = 0;
        for (Map.Entry<String, DockerTestContainer> entry : dockerTagToContainerInfo.entrySet()) {
            if (currentSubsetSize >= configOptionsConfig.getMaxRunningContainerShutdowns()) {
                containersSubsets.add(new HashSet<>());
                containerSetsIdx += 1;
                currentSubsetSize = 0;
            }
            containersSubsets.get(containerSetsIdx).add(entry.getKey());
            currentSubsetSize += 1;
        }

        LOGGER.info("Shutdown and clear all containers. This may take a while...");
        // Shutdown all containers
        for (Set<String> notRunningSubset : containersSubsets) {
            shutdownContainerSet(notRunningSubset);
        }
    }

    /**
     * Shutdown a set of docker containers. The amount of containers shutdown simultaneously is
     * defined in the config options config
     *
     * @param dockerTagsToShutdown - The tags of the containers to shutdown
     */
    protected synchronized void shutdownContainerSet(Set<String> dockerTagsToShutdown) {
        Set<String> failedShutdownTags = new HashSet<>();
        // Start all containers that have to be shutdown
        for (String entry : dockerTagsToShutdown) {
            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(entry);
            if (containerInfo == null) {
                continue;
            }
            if (containerInfo.getContainerState() == DockerContainerState.INVALID) {
                continue;
            }
            runContainer(containerInfo);
        }
        // Little delay to give containers time to start properly
        try {
            Thread.sleep(800);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        for (String entry : dockerTagsToShutdown) {
            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(entry);
            if (containerInfo == null) {
                continue;
            }
            if (containerInfo.getContainerState() == DockerContainerState.INVALID) {
                continue;
            }
            runContainer(containerInfo);

            try {
                containerInfo.sendHttpRequestToManager("shutdown");
            } catch (RuntimeException ex) {
                ex.printStackTrace();
                failedShutdownTags.add(entry);
            }
        }

        // Wait for containers to shutdown properly and remove them afterwards
        for (String entry : dockerTagsToShutdown) {
            if (failedShutdownTags.contains(entry)) {
                continue;
            }

            DockerTestContainer containerInfo = dockerTagToContainerInfo.get(entry);
            if (containerInfo.getContainerState() == DockerContainerState.INVALID) {
                continue;
            }
            // Wait for container to finish
            try {
                containerInfo.waitForState(DockerContainerState.NOT_RUNNING, 600000); // 10 min
            } catch (TimeoutException e) {
                LOGGER.error(
                        String.format(
                                "Cannot properly shutdown docker container with tag '%s'.",
                                containerInfo.getDockerTag()));
            }

            // Remove the container afterwards
            containerInfo.remove();
        }
    }

    /* === Misc === */

    /**
     * Computes the dockerTag that is assigned to a specific optionSet (which also depends on the
     * library version)
     *
     * @param optionSet - the option set to create the docker tag for
     * @return the resulting docker tag
     */
    protected String getDockerTagFromOptionSet(
            Set<ConfigurationOptionDerivationParameter> optionSet) {
        String cliOptions = createConfigOptionCliString(optionSet);
        return DockerBuilder.getDefaultTag(
                dockerTlsImplementation, libraryVersion, libraryConnectionRole, cliOptions);
    }

    /**
     * Creates the commandline arguments necessary for the building the passed option set (using the
     * library specific translation). The resulting list is sorted alphabetically so it is
     * deterministic.
     *
     * <p>It is assumed that options are defined in any order in a single command line command.
     * (Must be overridden by subclasses otherwise).
     *
     * @param optionSet - the set of configuration options.
     * @return the sorted list of command line options
     */
    protected String createConfigOptionCliString(
            Set<ConfigurationOptionDerivationParameter> optionSet) {
        Map<ConfigOptionParameterType, ConfigOptionValueTranslation> optionsToTranslationMap =
                configOptionsConfig.getOptionsToTranslationMap();
        List<String> optionsCliList = new ArrayList<>();
        for (ConfigurationOptionDerivationParameter optionParameter : optionSet) {
            String cliOption =
                    translateOptionValue(optionParameter, optionsToTranslationMap).trim();
            if (!cliOption.isEmpty()) {
                optionsCliList.add(cliOption);
            }
        }
        // Sort the options alphabetically. This is used to obtain deterministic results independent
        // of the Set's iteration order.
        optionsCliList.sort(Comparator.comparing(String::toString));

        return Strings.join(" ", optionsCliList);
    }

    /**
     * Makes a container running. If it is paused it will be unpaused. If its not running it will be
     * started. It waits for the running state.
     *
     * @param container - The container to make running.
     */
    protected synchronized void runContainer(DockerTestContainer container) {
        try {
            if (container.getContainerState() == DockerContainerState.NOT_RUNNING) {
                container.startAndWait();
            } else if (container.getContainerState() == DockerContainerState.PAUSED) {
                container.unpauseAndWait();
            } else if (container.getContainerState() == DockerContainerState.INVALID) {
                throw new IllegalStateException(
                        String.format(
                                "Cannot run container in state %s.", DockerContainerState.INVALID));
            }
        } catch (TimeoutException e) {
            e.printStackTrace();
            throw new RuntimeException(
                    String.format(
                            "Cannot start/unpause container with tag '%s'.",
                            container.getDockerTag()));
        }
    }

    public Map<String, DockerTestContainer> getDockerTagToContainerInfoMap() {
        return dockerTagToContainerInfo;
    }

    /**
     * Translates a given configuration option to a tls library specific string.
     *
     * @param optionParameter - the configuration option to translate (including its set value)
     * @param optionsToTranslationMap - the translation map of the configuration options config
     * @return the translated string
     */
    protected String translateOptionValue(
            ConfigurationOptionDerivationParameter optionParameter,
            Map<ConfigOptionParameterType, ConfigOptionValueTranslation> optionsToTranslationMap) {
        ConfigurationOptionValue value = optionParameter.getSelectedValue();
        if (value == null) {
            throw new IllegalArgumentException(
                    "Passed option parameter has no selected value yet.");
        }
        ParameterType parameterType = optionParameter.getParameterIdentifier().getParameterType();
        if (!(parameterType instanceof ConfigOptionParameterType)) {
            throw new IllegalArgumentException(
                    "Passed derivation parameter is not of type ConfigOptionDerivationType.");
        }
        ConfigOptionParameterType optionType = (ConfigOptionParameterType) parameterType;

        if (!optionsToTranslationMap.containsKey(optionType)) {
            throw new IllegalStateException(
                    "The ConfigurationOptionsConfig's translation map does not contain the passed type");
        }

        ConfigOptionValueTranslation translation = optionsToTranslationMap.get(optionType);

        if (translation instanceof FlagTranslation) {
            FlagTranslation flagTranslation = (FlagTranslation) translation;
            if (!value.isFlag()) {
                throw new IllegalStateException(
                        "The ConfigurationOptionsConfig's translation is a flag, but the ConfigurationOptionValue isn't. Value can't be translated.");
            }

            if (value.isOptionSet()) {
                return flagTranslation.getDataIfSet();
            } else {
                return flagTranslation.getDataIfNotSet();
            }
        } else if (translation instanceof SingleValueOptionTranslation) {
            SingleValueOptionTranslation singleValueTranslation =
                    (SingleValueOptionTranslation) translation;
            if (value.isFlag()) {
                throw new IllegalStateException(
                        "The ConfigurationOptionsConfig's translation has a value, but the ConfigurationOptionValue is a flag. Value can't be translated.");
            }
            List<String> optionValues = value.getOptionValues();
            if (optionValues.size() != 1) {
                throw new IllegalStateException(
                        "The ConfigurationOptionsConfig's translation has a single value, but the ConfigurationOptionValue is not a single value. Value can't be translated.");
            }
            String optionValue = optionValues.get(0);

            String translatedName = singleValueTranslation.getIdentifier();
            String translatedValue = singleValueTranslation.getValueTranslation(optionValue);

            return String.format("%s=%s", translatedName, translatedValue);
        } else {
            throw new UnsupportedOperationException(
                    String.format(
                            "The DockerBasedBuildManager does not support translations '%s'.",
                            translation.getClass()));
        }
    }
}
