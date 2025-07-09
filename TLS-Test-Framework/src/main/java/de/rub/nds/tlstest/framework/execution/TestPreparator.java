package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.junit.extension.EndpointConditionExtension;
import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.execution.TlsClientScanner;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsExtension;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.TestCOMultiClientDelegate;
import java.io.*;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.engine.TestSource;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.*;

/**
 * The TestPreparator is used before a test execution. It ensures, that the server or client is
 * ready to be tested and runs a feature extraction scan.
 */
public class TestPreparator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsAnvilConfig tlsAnvilConfig;
    private final TestContext testContext;

    private boolean targetIsReady = false;

    public TestPreparator(TlsAnvilConfig tlsAnvilConfig, TestContext testContext) {
        this.tlsAnvilConfig = tlsAnvilConfig;
        this.testContext = testContext;
    }

    /**
     * Save the supplied FeatureExtractionResult to the disk. Two files are created: a JavaObject
     * .ser and a readable .json file.
     *
     * @param report the FeatureExtractionResult created through TLS-Scanner
     */
    private void saveToCache(FeatureExtractionResult report) {
        String fileName;
        if (tlsAnvilConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName =
                    "client_"
                            + HexFormat.of()
                                    .toHexDigits(
                                            tlsAnvilConfig
                                                    .getTestClientDelegate()
                                                    .getTriggerScriptCommand()
                                                    .hashCode());
        } else {
            fileName =
                    tlsAnvilConfig.getTestServerDelegate().getExtractedHost()
                            + "_"
                            + tlsAnvilConfig.getTestServerDelegate().getExtractedPort();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker());
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            Path cachePath = Paths.get("cache", fileName);
            Files.createDirectories(Paths.get("cache"));
            mapper.writeValue(new File(cachePath + ".json"), report);

            FileOutputStream fos = new FileOutputStream(cachePath + ".ser");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(report);
            oos.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a FeatureExtractionResult, if a corresponding file for the given configuration is
     * found on disk. Only the serialized Java-Object .ser file is used.
     *
     * @return the FeatureExtractionResult or null, if not found
     */
    private FeatureExtractionResult loadFromCache() {
        String fileName;
        if (tlsAnvilConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName =
                    "client_"
                            + HexFormat.of()
                                    .toHexDigits(
                                            tlsAnvilConfig
                                                    .getTestClientDelegate()
                                                    .getTriggerScriptCommand()
                                                    .hashCode());
        } else {
            fileName =
                    tlsAnvilConfig.getTestServerDelegate().getExtractedHost()
                            + "_"
                            + tlsAnvilConfig.getTestServerDelegate().getExtractedPort();
        }
        fileName = fileName + ".ser";
        File cachedFile = new File(Paths.get("cache", fileName).toString());
        if (cachedFile.exists() && !tlsAnvilConfig.getAnvilTestConfig().isIgnoreCache()) {
            try {
                FileInputStream fis = new FileInputStream(cachedFile);
                ObjectInputStream ois = new ObjectInputStream(fis);
                LOGGER.info("Reading cached ScanReport");
                return (FeatureExtractionResult) ois.readObject();
            } catch (InvalidClassException e) {
                LOGGER.info("Cached SiteReport appears to be outdated");
            } catch (Exception e) {
                LOGGER.error("Failed to load cached ScanReport {}", fileName, e);
            }
        } else if (cachedFile.exists() && tlsAnvilConfig.getAnvilTestConfig().isIgnoreCache()) {
            LOGGER.info("Ignoring cached ScanReport as configurated");
        } else {
            LOGGER.info("No matching ScanReport has been cached yet");
        }

        return null;
    }

    /**
     * Runs the client trigger script stored in the config until a client connects. Blocks until
     * success.
     */
    private void waitForClient() {
        try {
            new Thread(
                            () -> {
                                while (!targetIsReady && !testContext.isAborted()) {
                                    LOGGER.info("Waiting for the client to get ready...");
                                    try {
                                        State state = new State();
                                        tlsAnvilConfig
                                                .getTestClientDelegate()
                                                .executeTriggerScript(state);
                                    } catch (Exception ignored) {
                                    }

                                    try {
                                        Thread.sleep(1000);
                                    } catch (Exception ignored) {
                                    }
                                }
                            })
                    .start();
            if (!tlsAnvilConfig.isUseDTLS()) {
                Socket socket = tlsAnvilConfig.getTestClientDelegate().getServerSocket().accept();
                targetIsReady = true;
                socket.close();
            } else {
                DatagramSocket socket =
                        new DatagramSocket(tlsAnvilConfig.getTestClientDelegate().getPort());

                byte[] buf = new byte[256];

                while (!targetIsReady) {
                    try {
                        DatagramPacket packet = new DatagramPacket(buf, buf.length);
                        socket.receive(packet);
                        if (packet.getLength() > 0) {
                            targetIsReady = true;
                            socket.close();
                        }

                    } catch (Exception ignored) {
                        ignored.printStackTrace();
                    }
                }
            }
        } catch (Exception ex) {
            LOGGER.error(ex);
            throw new RuntimeException("Failed to await client connection");
        }

        LOGGER.info("Client is ready, preparing client exploration...");
    }

    /**
     * Tries to make a TCP handshake connection with the server host given in the config. Blocks
     * until success.
     */
    private void waitForServer() {
        OutboundConnection connection = tlsAnvilConfig.createConfig().getDefaultClientConnection();

        try {
            Socket conTest = null;
            DatagramSocket conTestDtls = null;
            while (!targetIsReady && !testContext.isAborted()) {
                try {
                    if (tlsAnvilConfig.isUseDTLS()) {
                        String connectionEndpoint;
                        if (connection.getIp() != null) {
                            connectionEndpoint = connection.getIp();
                        } else {
                            connectionEndpoint = connection.getHostname();
                        }

                        conTestDtls = new DatagramSocket();
                        conTestDtls.connect(
                                InetAddress.getByName(connectionEndpoint), connection.getPort());
                        targetIsReady = conTestDtls.isConnected(); // TODO always true
                    } else {
                        String connectionEndpoint;
                        if (connection.getIp() != null) {
                            connectionEndpoint = connection.getIp();
                        } else {
                            connectionEndpoint = connection.getHostname();
                        }
                        conTest = new Socket(connectionEndpoint, connection.getPort());
                        targetIsReady = conTest.isConnected();
                    }
                } catch (Exception e) {
                    LOGGER.warn("Server not yet available (" + e.getLocalizedMessage() + ")");
                    Thread.sleep(1000);
                }
            }

            if (tlsAnvilConfig.isUseDTLS()) {
                if (conTestDtls != null) conTestDtls.close();
            } else {
                if (conTest != null) conTest.close();
            }
        } catch (Exception e) {
            LOGGER.error("Error during server preparation", e);
            System.exit(2);
        }
    }

    /**
     * Prepare server test execution: Waiting until the server is ready, and starting a feature
     * extraction scan if necessary.
     */
    private void serverTestPreparation() {
        waitForServer();

        FeatureExtractionResult cachedReport = loadFromCache();
        if (cachedReport != null) {
            testContext.setFeatureExtractionResult(cachedReport);
            return;
        }

        LOGGER.info("Server available, starting TLS-Scanner");

        TlsServerScanner scanner =
                getServerScanner(
                        tlsAnvilConfig.getGeneralDelegate(),
                        tlsAnvilConfig.getTestServerDelegate(),
                        testContext.getStateExecutor(),
                        tlsAnvilConfig.getAnvilTestConfig().getConnectionTimeout(),
                        tlsAnvilConfig.isUseDTLS(),
                        tlsAnvilConfig.getTestServerDelegate().isDoNotSendSNIExtension());

        ServerReport serverReport = scanner.scan();
        serverReport.putResult(TlsAnalyzedProperty.HTTPS_HEADER, TestResults.ERROR_DURING_TEST);
        FeatureExtractionResult report =
                ServerFeatureExtractionResult.fromServerScanReport(serverReport);
        if (!tlsAnvilConfig.getAnvilTestConfig().isIgnoreCache()) {
            saveToCache(report);
        }

        testContext.setFeatureExtractionResult(report);
        LOGGER.debug("TLS-Scanner finished!");
    }

    /**
     * Creates a scanner object to perform the feature extraction. The code is used both for a
     * single given server and for configuration option tests against self-built docker containers.
     *
     * @param generalDelegate - the general delegate to use
     * @param testServerDelegate - the TestServerDelegate to use
     * @param executor - the ParallelExecutor to use
     * @return TlsServerScanner the object ready for execution
     */
    public static TlsServerScanner getServerScanner(
            GeneralDelegate generalDelegate,
            TestServerDelegate testServerDelegate,
            ParallelExecutor executor,
            int timeout,
            boolean dtls,
            boolean doNotSendSNI) {
        ServerScannerConfig scannerConfig =
                new ServerScannerConfig(generalDelegate, testServerDelegate);
        scannerConfig.setTimeout(timeout);
        scannerConfig.setDoNotSendSNIExtension(doNotSendSNI);
        if (dtls) {
            scannerConfig.getDtlsDelegate().setDTLS(true);
        }
        scannerConfig
                .getExecutorConfig()
                .setProbes(
                        TlsProbeType.COMMON_BUGS,
                        TlsProbeType.CIPHER_SUITE,
                        TlsProbeType.CERTIFICATE,
                        TlsProbeType.COMPRESSIONS,
                        TlsProbeType.NAMED_GROUPS,
                        TlsProbeType.PROTOCOL_VERSION,
                        TlsProbeType.EC_POINT_FORMAT,
                        TlsProbeType.RESUMPTION,
                        TlsProbeType.EXTENSIONS,
                        TlsProbeType.RECORD_FRAGMENTATION,
                        TlsProbeType.HELLO_RETRY,
                        TlsProbeType.HTTP_HEADER,
                        TlsProbeType.CONNECTION_CLOSING_DELTA,
                        TlsProbeType.SIGNATURE_AND_HASH);
        scannerConfig.getExecutorConfig().setOverallThreads(1);
        scannerConfig.getExecutorConfig().setParallelProbes(1);
        scannerConfig.setConfigSearchCooldown(true);
        TlsServerScanner scanner = new TlsServerScanner(scannerConfig, executor);
        return scanner;
    }

    /**
     * Prepare client test execution: Waiting until the client is ready and starting a feature
     * extraction scan if necessary.
     */
    private void clientTestPreparation() {
        waitForClient();
        ParallelExecutor preparedExecutor = testContext.getStateExecutor();
        setGlobalClientTestCallbacks(preparedExecutor);

        ClientFeatureExtractionResult cachedReport =
                (ClientFeatureExtractionResult) loadFromCache();
        if (cachedReport != null) {
            testContext.setFeatureExtractionResult(cachedReport);
            testContext.setReceivedClientHelloMessage(cachedReport.getReceivedClientHello());
            return;
        }

        ClientHelloMessage clientHello = catchClientHello(preparedExecutor);
        if (clientHello == null) {
            throw new RuntimeException("Failed to receive a ClientHello in test preparation");
        }
        LOGGER.info("Received Client Hello. Starting Client-Scanner for feature extraction.");

        // Initialize Client Scanner with null trigger script as our externally managed
        // ParallelExecutor handles the trigger script for the entire execution
        TlsClientScanner clientScanner =
                getClientScanner(
                        tlsAnvilConfig.getDelegate(TestClientDelegate.class).getPort(),
                        preparedExecutor,
                        tlsAnvilConfig.getAnvilTestConfig().getConnectionTimeout(),
                        null,
                        tlsAnvilConfig.isUseDTLS());

        String identifier =
                tlsAnvilConfig.getAnvilTestConfig().getIdentifier() == null
                        ? "client"
                        : tlsAnvilConfig.getAnvilTestConfig().getIdentifier();
        ClientFeatureExtractionResult extractionResult =
                ClientFeatureExtractionResult.fromClientScanReport(
                        clientScanner.scan(), identifier);

        extractionResult.setReceivedClientHello(clientHello);
        if (!tlsAnvilConfig.getAnvilTestConfig().isIgnoreCache()) {
            saveToCache(extractionResult);
        }
        testContext.setReceivedClientHelloMessage(clientHello);
        testContext.setFeatureExtractionResult(extractionResult);
    }

    /**
     * Sets the callbacks required for all TLS sessions to be established with the tested client.
     *
     * @param preparedExecutor The ParallelExecutor instance used by the feature extraction and the
     *     tests
     */
    private void setGlobalClientTestCallbacks(ParallelExecutor preparedExecutor) {
        // Ensure we always retain our external socket
        preparedExecutor.setDefaultBeforeTransportPreInitCallback(getSocketManagementCallback());
        // Ensure we always trigger the client
        preparedExecutor.setDefaultBeforeTransportInitCallback(
                tlsAnvilConfig.getTestClientDelegate().getTriggerScript());

        if (tlsAnvilConfig.isUseDTLS()) {
            // todo: set reexecution callback for dtls in parallel executor once it is updated
        }
    }

    /**
     * Creates a scanner object to perform the feature extraction. The code is used both for a
     * single given client and for configuration option tests against self-built docker containers.
     *
     * @param port the port to listen on
     * @param preparedExecutor the ParallelExecutor to use
     * @return TlsClientScanner the object ready for execution
     */
    public static TlsClientScanner getClientScanner(
            Integer port,
            ParallelExecutor preparedExecutor,
            int timeout,
            Function<State, Integer> externalRunCallback,
            boolean dtls) {

        TlsClientScanner clientScanner =
                new TlsClientScanner(
                        getClientScannerConfig(port, timeout, externalRunCallback, dtls),
                        preparedExecutor);
        return clientScanner;
    }

    public static ClientScannerConfig getClientScannerConfig(
            Integer port, int timeout, Function<State, Integer> externalRunCallback, boolean dtls) {
        ClientScannerConfig clientScannerConfig = new ClientScannerConfig(new GeneralDelegate());
        List<ProbeType> probes = new LinkedList<>();
        probes.add(TlsProbeType.BASIC);
        probes.add(TlsProbeType.CIPHER_SUITE);
        probes.add(TlsProbeType.PROTOCOL_VERSION);
        probes.add(TlsProbeType.NAMED_GROUPS);
        probes.add(TlsProbeType.EC_POINT_FORMAT);
        probes.add(TlsProbeType.SERVER_CERTIFICATE_MINIMUM_KEY_SIZE);
        probes.add(TlsProbeType.CONNECTION_CLOSING_DELTA);
        probes.add(TlsProbeType.RECORD_FRAGMENTATION);
        probes.add(TlsProbeType.APPLICATION_MESSAGE);
        clientScannerConfig.getServerDelegate().setPort(port);
        clientScannerConfig.setTimeout(timeout);
        clientScannerConfig.getExecutorConfig().setProbes(probes);
        clientScannerConfig.setExternalRunCallback(externalRunCallback);
        if (dtls) {
            clientScannerConfig.getDtlsDelegate().setDTLS(true);
            probes.add(TlsProbeType.DTLS_FRAGMENTATION);
        } else {
            probes.add(TlsProbeType.RECORD_FRAGMENTATION);
        }
        return clientScannerConfig;
    }

    /**
     * Catches a ClientHello to perform non-combinatorial client tests. We assume that the client
     * always sends the same ClientHello (except for configuration option tests)
     *
     * @param executor
     * @return
     */
    private ClientHelloMessage catchClientHello(ParallelExecutor executor) {
        LOGGER.info("Attempting to receive a Client Hello");
        return catchClientHello(executor, tlsAnvilConfig.getTestClientDelegate().getPort());
    }

    public static ClientHelloMessage catchClientHello(ParallelExecutor executor, int port) {

        TlsAnvilConfig tlsAnvilConfig = TestContext.getInstance().getConfig();
        Config config = tlsAnvilConfig.createConfig();
        config.setDefaultServerConnection(new InboundConnection(port));
        WorkflowTrace catchHelloWorkflowTrace = new WorkflowTrace();
        catchHelloWorkflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        State catchHelloState = new State(config, catchHelloWorkflowTrace);
        StateExecutionTask catchHelloTask = new StateExecutionTask(catchHelloState, 2);
        executor.bulkExecuteTasks(catchHelloTask);

        return (ClientHelloMessage)
                WorkflowTraceResultUtil.getFirstReceivedMessage(
                        catchHelloWorkflowTrace, HandshakeMessageType.CLIENT_HELLO);
    }

    /**
     * Should be called before starting the testing phase to ensure server or client is ready and a
     * FeatureExtractionResult is set.
     *
     * @return returns true if preparation was successful, false if the test cannot be started
     */
    public boolean prepareTestExecution() {
        if (!tlsAnvilConfig.isParsedArgs()) {
            return false;
        }
        // no parallel execution for DTLS
        if (tlsAnvilConfig.getTestEndpointMode() == TestEndpointType.CLIENT
                && tlsAnvilConfig.isUseDTLS()
                && tlsAnvilConfig.getParallelHandshakes() > 1) {
            LOGGER.warn(
                    "Restricting parallel test cases to 1 as TLS-Attacker does not support parallel UDP connections");
            tlsAnvilConfig.setParallelHandshakes(1);
        }

        ParallelExecutor executor =
                ParallelExecutor.create(tlsAnvilConfig.getParallelHandshakes(), 1);
        executor.setTimeoutAction(tlsAnvilConfig.getTimeoutActionScript());
        executor.armTimeoutAction(20000);
        testContext.setStateExecutor(executor);

        LOGGER.info("Starting preparation phase");
        String configurationOptionsConfigFile = tlsAnvilConfig.getConfigOptionsConfigFile();
        if (!configurationOptionsConfigFile.isEmpty()) {
            LOGGER.info("Preparing configuration options environment");
            ConfigurationOptionsExtension.getInstance().load(configurationOptionsConfigFile);
        } else {
            this.tlsAnvilConfig.createConfig();
            if (this.tlsAnvilConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
                clientTestPreparation();
            } else if (this.tlsAnvilConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
                serverTestPreparation();
                ServerFeatureExtractionResult featureExtractionResult =
                        (ServerFeatureExtractionResult) testContext.getFeatureExtractionResult();
                AnvilContext.getInstance()
                        .getMapper()
                        .saveExtraFileToPath(
                                featureExtractionResult.getGuidelineChecks(), "guidelines");
            } else throw new RuntimeException("Invalid TestEndpointMode");

            try {
                Files.createDirectories(
                        Path.of(tlsAnvilConfig.getAnvilTestConfig().getOutputFolder()));
                Files.writeString(
                        Path.of(
                                tlsAnvilConfig.getAnvilTestConfig().getOutputFolder(),
                                "tls-scanner.txt"),
                        testContext.getFeatureExtractionResult().getTestReport());
            } catch (IOException | NullPointerException e) {
                LOGGER.error("Could not create scan report: ", e);
            }
        }

        if (testContext.getFeatureExtractionResult() == null) {
            throw new RuntimeException(
                    "Feature extraction result was not set after test preparation");
        }

        boolean startTestSuite = false;
        if (testContext.getFeatureExtractionResult().getSupportedVersions() == null
                || testContext.getFeatureExtractionResult().getSupportedVersions().isEmpty()) {
            LOGGER.error("Target does not support any ProtocolVersion");
        } else if (testContext.getFeatureExtractionResult().getCipherSuites().isEmpty()
                && testContext
                        .getFeatureExtractionResult()
                        .getSupportedTls13CipherSuites()
                        .isEmpty()) {
            LOGGER.error("Target does not support any CipherSuites");
        } else if (!testContext
                        .getFeatureExtractionResult()
                        .getSupportedVersions()
                        .contains(ProtocolVersion.TLS12)
                && !testContext
                        .getFeatureExtractionResult()
                        .getSupportedVersions()
                        .contains(ProtocolVersion.TLS13)
                && !testContext
                        .getFeatureExtractionResult()
                        .getSupportedVersions()
                        .contains(ProtocolVersion.DTLS12)) {
            LOGGER.error("Target does not support any ProtocolVersion that the Testsuite supports");
        } else {
            startTestSuite = true;
        }

        logCommonDerivationValues();

        LOGGER.info("Prepartion finished!");
        return startTestSuite;
    }

    private void logCommonDerivationValues() {
        FeatureExtractionResult featureExtractionResult =
                TestContext.getInstance().getFeatureExtractionResult();
        LOGGER.info(
                "Supported Protocol Versions: {}",
                featureExtractionResult.getSupportedVersions().stream()
                        .map(ProtocolVersion::toString)
                        .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported (D)TLS 1.2 Named Groups: {}",
                featureExtractionResult.getNamedGroups().stream()
                        .map(NamedGroup::toString)
                        .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported (D)TLS 1.3 Named Groups: {}",
                featureExtractionResult.getTls13Groups().stream()
                        .map(NamedGroup::toString)
                        .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported (D)TLS 1.2 Cipher Suites: {}",
                featureExtractionResult.getCipherSuites().stream()
                        .map(CipherSuite::toString)
                        .collect(Collectors.joining(",")));

        LOGGER.info(
                "Supported (D)TLS 1.3 Cipher Suites: {}",
                featureExtractionResult.getSupportedTls13CipherSuites().stream()
                        .map(CipherSuite::toString)
                        .collect(Collectors.joining(",")));
    }

    /**
     * Ensures that the ClientScanner always uses the externally managed socket
     *
     * @return Function to set socket in created state
     */
    public static Function<State, Integer> getSocketManagementCallback() {
        return (State state) -> {
            TransportHandler transportHandler;
            TestContext context = TestContext.getInstance();
            TestClientDelegate testClientDelegate = context.getConfig().getTestClientDelegate();
            if (context.getConfig().isUseDTLS()) {
                transportHandler =
                        new ServerUdpTransportHandler(
                                context.getConfig().getAnvilTestConfig().getConnectionTimeout(),
                                testClientDelegate.getPort());
            } else {
                ServerSocket socket;
                if (testClientDelegate instanceof TestCOMultiClientDelegate) {
                    socket =
                            ((TestCOMultiClientDelegate)
                                            TestContext.getInstance()
                                                    .getConfig()
                                                    .getTestClientDelegate())
                                    .getServerSocket(state.getConfig());
                } else {
                    socket = testClientDelegate.getServerSocket();
                }
                transportHandler =
                        new ServerTcpTransportHandler(
                                context.getConfig().getAnvilTestConfig().getConnectionTimeout(),
                                context.getConfig().getAnvilTestConfig().getConnectionTimeout(),
                                socket);
            }
            state.getTlsContext().setTransportHandler(transportHandler);
            return 0;
        };
    }

    // This method is supposed to replace the callback set in the WorkflowRunner as we also want to
    // apply it to the DTLS client scanner.
    // However, the ParallelExecutor does not except a default reexecution callback yet.
    private static Function<State, Integer> getDtlsClientTestReexecutionCallback() {
        return (State state) -> {
            ServerUdpTransportHandler udpTransportHandler =
                    (ServerUdpTransportHandler) state.getTlsContext().getTransportHandler();
            try {
                if (udpTransportHandler.isInitialized() && !udpTransportHandler.isClosed()) {
                    udpTransportHandler.closeConnection();
                }
            } catch (IOException ex) {
                LOGGER.error(ex);
                return 1;
            }
            return 0;
        };
    }

    private static boolean countTests(
            TestIdentifier i,
            ProtocolVersion versionToCount,
            TestEndpointType endpointTypeToCount,
            TestEndpointType executionTestEndpointType) {
        TestSource source = i.getSource().orElse(null);
        if (!i.isTest() && (source == null || !source.getClass().equals(MethodSource.class))) {
            return false;
        }

        MethodSource methodSource = (MethodSource) source;
        Class<?> testClass = methodSource.getJavaClass();
        Method testMethod = methodSource.getJavaMethod();
        TestEndpointType requiredEndpointType =
                EndpointConditionExtension.endpointOfMethod(testMethod, testClass);
        Set<ProtocolVersion> versionList = new HashSet<>();
        versionList.add(versionToCount);
        return TlsVersionCondition.versionsMatch(
                        versionList,
                        TlsVersionCondition.getSupportedTestVersions(testMethod, testClass))
                && requiredEndpointType != null
                && (executionTestEndpointType == TestEndpointType.BOTH
                        || requiredEndpointType == endpointTypeToCount
                        || executionTestEndpointType == endpointTypeToCount)
                && requiredEndpointType.isMatchingTestEndpointType(executionTestEndpointType);
    }

    /**
     * Logs, how many tests were discovered for every TLS version, as well as test strength and
     * connection timeout.
     *
     * @param testPlan the testPlan, supplied by JUnits discovery
     */
    public static void printTestInfo(TestPlan testPlan) {
        LOGGER.info("Scheduled test templates:");
        TestEndpointType executionEndpointType =
                TestContext.getInstance().getConfig().getTestEndpointMode();
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            long clientDtls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.DTLS12,
                                            TestEndpointType.CLIENT,
                                            executionEndpointType));
            long serverDtls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.DTLS12,
                                            TestEndpointType.SERVER,
                                            executionEndpointType));
            LOGGER.info(
                    "DTLS 1.2 tests: {} client tests, {} server tests", clientDtls12, serverDtls12);
        } else {
            long clientTls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS12,
                                            TestEndpointType.CLIENT,
                                            executionEndpointType));
            long serverTls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS12,
                                            TestEndpointType.SERVER,
                                            executionEndpointType));
            long clientTls13 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS13,
                                            TestEndpointType.CLIENT,
                                            executionEndpointType));
            long serverTls13 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS13,
                                            TestEndpointType.SERVER,
                                            executionEndpointType));
            LOGGER.info(
                    "TLS 1.2 tests: {} client tests, {} server tests", clientTls12, serverTls12);
            LOGGER.info(
                    "TLS 1.3 tests: {} client tests, {} server tests", clientTls13, serverTls13);
        }
        LOGGER.info(
                "Testing using default strength "
                        + TestContext.getInstance().getConfig().getAnvilTestConfig().getStrength());
        LOGGER.info(
                "Default timeout "
                        + TestContext.getInstance()
                                .getConfig()
                                .getAnvilTestConfig()
                                .getConnectionTimeout()
                        + " ms");
    }
}
