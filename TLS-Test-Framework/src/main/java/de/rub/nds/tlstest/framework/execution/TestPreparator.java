package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.execution.TlsClientScanner;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.TlsTestConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.engine.TestSource;
import org.junit.platform.engine.TestTag;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.*;

/**
 * The TestPreparator is used before a test execution. It ensures, that the server or client is
 * ready to be tested and runs a feature extraction scan.
 */
public class TestPreparator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsTestConfig testConfig;
    private final TestContext testContext;
    private Process tcpdumpProcess;

    private boolean targetIsReady = false;

    public TestPreparator(TlsTestConfig testConfig, TestContext testContext) {
        this.testConfig = testConfig;
        this.testContext = testContext;
    }

    /**
     * Save the supplied FeatureExtractionResult to the disk. Two files are created: a JavaObject
     * .ser and a readable .json file.
     *
     * @param report the FeatureExtractionResult created through TLS-Scanner
     */
    private void saveToCache(@Nonnull FeatureExtractionResult report) {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName =
                    testConfig.getTestServerDelegate().getExtractedHost()
                            + "_"
                            + testConfig.getTestServerDelegate().getExtractedPort();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker());
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            mapper.writeValue(new File(fileName + ".json"), report);

            FileOutputStream fos = new FileOutputStream(fileName + ".ser");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(report);
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
    @Nullable
    private FeatureExtractionResult loadFromCache() {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName =
                    testConfig.getTestServerDelegate().getExtractedHost()
                            + "_"
                            + testConfig.getTestServerDelegate().getExtractedPort()
                            + ".ser";
        }

        File f = new File(fileName);
        if (f.exists() && !testConfig.getAnvilTestConfig().isIgnoreCache()) {
            try {
                FileInputStream fis = new FileInputStream(fileName);
                ObjectInputStream ois = new ObjectInputStream(fis);
                LOGGER.info("Reading cached ScanReport");
                return (FeatureExtractionResult) ois.readObject();
            } catch (InvalidClassException e) {
                LOGGER.info("Cached SiteReport appears to be outdated");
            } catch (Exception e) {
                LOGGER.error("Failed to load cached ScanReport");
            }
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
                                        testConfig
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
            if (!testConfig.isUseDTLS()) {
                Socket socket = testConfig.getTestClientDelegate().getServerSocket().accept();
                targetIsReady = true;
                socket.close();
            } else {
                try {
                    DatagramSocket socket =
                            new DatagramSocket(testConfig.getTestClientDelegate().getPort());

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
                } catch (SocketException e) {
                    throw new RuntimeException(e);
                }
            }
        } catch (Exception ex) {
            LOGGER.error(ex);
            throw new RuntimeException("Failed to await client connection");
        }

        LOGGER.info("Client is ready, prepapring client exploration...");
    }

    /**
     * Tries to make a TCP handshake connection with the server host given in the config. Blocks
     * until success.
     */
    private void waitForServer() {
        OutboundConnection connection = testConfig.createConfig().getDefaultClientConnection();

        try {
            Socket conTest = null;
            DatagramSocket conTestDtls = null;
            while (!targetIsReady && !testContext.isAborted()) {
                try {
                    if (testConfig.isUseDTLS()) {
                        String connectionEndpoint;
                        if (connection.getHostname() != null) {
                            connectionEndpoint = connection.getHostname();
                        } else {
                            connectionEndpoint = connection.getIp();
                        }

                        conTestDtls = new DatagramSocket();
                        conTestDtls.connect(
                                InetAddress.getByName(connectionEndpoint), connection.getPort());
                        targetIsReady = conTestDtls.isConnected(); // TODO always true
                    } else {
                        String connectionEndpoint;
                        if (connection.getHostname() != null) {
                            connectionEndpoint = connection.getHostname();
                        } else {
                            connectionEndpoint = connection.getIp();
                        }
                        conTest = new Socket(connectionEndpoint, connection.getPort());
                        targetIsReady = conTest.isConnected();
                    }
                } catch (Exception e) {
                    LOGGER.warn("Server not yet available (" + e.getLocalizedMessage() + ")");
                    Thread.sleep(1000);
                }
            }
            if (testConfig.isUseDTLS()) {
                conTestDtls.close();
            } else {
                conTest.close();
            }
        } catch (Exception e) {
            LOGGER.error(e);
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
        ServerScannerConfig scannerConfig =
                new ServerScannerConfig(
                        testConfig.getGeneralDelegate(), testConfig.getTestServerDelegate());
        scannerConfig.setTimeout(testConfig.getAnvilTestConfig().getConnectionTimeout());
        Config config = scannerConfig.createConfig();
        config.setAddServerNameIndicationExtension(
                testConfig.createConfig().isAddServerNameIndicationExtension());
        config.getDefaultClientConnection().setConnectionTimeout(0);

        if (testConfig.isUseDTLS()) {
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

        TlsServerScanner scanner =
                new TlsServerScanner(scannerConfig, testContext.getStateExecutor());

        FeatureExtractionResult report =
                ServerFeatureExtractionResult.fromServerScanReport(scanner.scan());
        saveToCache(report);

        testContext.setFeatureExtractionResult(report);
        LOGGER.debug("TLS-Scanner finished!");
    }

    /**
     * Prepare client test execution: Waiting until the client is ready and starting a feature
     * extraction scan if necessary.
     */
    private void clientTestPreparation() {
        waitForClient();

        ClientFeatureExtractionResult cachedReport =
                (ClientFeatureExtractionResult) loadFromCache();
        if (cachedReport != null) {
            testContext.setFeatureExtractionResult(cachedReport);
            testContext.setReceivedClientHelloMessage(cachedReport.getReceivedClientHello());
            return;
        }

        ParallelExecutor preparedExecutor =
                new ParallelExecutor(testConfig.getAnvilTestConfig().getParallelTestCases(), 2);
        preparedExecutor.setDefaultBeforeTransportPreInitCallback(getSocketManagementCallback());

        ClientHelloMessage clientHello = catchClientHello(preparedExecutor);
        if (clientHello == null) {
            throw new RuntimeException("Failed to receive a ClientHello in test preparation");
        }
        LOGGER.info("Received Client Hello. Starting Client-Scanner for feature extraction.");

        ClientScannerConfig clientScannerConfig = new ClientScannerConfig(new GeneralDelegate());
        List<ProbeType> probes = new LinkedList<>();
        probes.add(TlsProbeType.BASIC);
        probes.add(TlsProbeType.CIPHER_SUITE);
        probes.add(TlsProbeType.PROTOCOL_VERSION);
        probes.add(TlsProbeType.NAMED_GROUPS);
        probes.add(TlsProbeType.RECORD_FRAGMENTATION);
        probes.add(TlsProbeType.EC_POINT_FORMAT);
        probes.add(TlsProbeType.SERVER_CERTIFICATE_MINIMUM_KEY_SIZE);
        probes.add(TlsProbeType.CONNECTION_CLOSING_DELTA);
        probes.add(TlsProbeType.APPLICATION_MESSAGE);
        clientScannerConfig
                .getServerDelegate()
                .setPort(testConfig.getDelegate(TestClientDelegate.class).getPort());
        clientScannerConfig.setTimeout(testConfig.getAnvilTestConfig().getConnectionTimeout());
        clientScannerConfig.getExecutorConfig().setProbes(probes);
        clientScannerConfig.setExternalRunCallback(
                testConfig.getTestClientDelegate().getTriggerScript());
        if (testConfig.isUseDTLS()) {
            clientScannerConfig.getDtlsDelegate().setDTLS(true);
        }

        TlsClientScanner clientScanner =
                new TlsClientScanner(clientScannerConfig, preparedExecutor);

        String identifier =
                testConfig.getAnvilTestConfig().getIdentifier() == null
                        ? "client"
                        : testConfig.getAnvilTestConfig().getIdentifier();
        ClientFeatureExtractionResult extractionResult =
                ClientFeatureExtractionResult.fromClientScanReport(
                        clientScanner.scan(), identifier);

        extractionResult.setReceivedClientHello(clientHello);
        saveToCache(extractionResult);
        testContext.setReceivedClientHelloMessage(clientHello);
        testContext.setFeatureExtractionResult(extractionResult);
    }

    private ClientHelloMessage catchClientHello(ParallelExecutor executor) {
        LOGGER.info("Attempting to receive a Client Hello");
        Config config = testConfig.createConfig();
        WorkflowTrace catchHelloWorkflowTrace = new WorkflowTrace();
        catchHelloWorkflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        State catchHelloState = new State(config, catchHelloWorkflowTrace);
        StateExecutionTask catchHelloTask = new StateExecutionTask(catchHelloState, 2);
        catchHelloTask.setBeforeTransportInitCallback(
                testConfig.getTestClientDelegate().getTriggerScript());
        catchHelloTask.setBeforeTransportPreInitCallback(getSocketManagementCallback());
        executor.bulkExecuteTasks(catchHelloTask);

        return (ClientHelloMessage)
                WorkflowTraceUtil.getFirstReceivedMessage(
                        HandshakeMessageType.CLIENT_HELLO, catchHelloWorkflowTrace);
    }

    /**
     * Should be called before starting the testing phase to ensure server or client is ready and a
     * FeatureExtractionResult is set.
     *
     * @return returns true if preparation was successful, false if the test cannot be started
     */
    public boolean prepareTestExecution() {
        if (!testConfig.isParsedArgs()) {
            return false;
        }

        ParallelExecutor executor =
                new ParallelExecutor(testConfig.getAnvilTestConfig().getParallelTestCases(), 2);
        executor.setTimeoutAction(testConfig.getTimeoutActionScript());
        executor.armTimeoutAction(20000);
        testContext.setStateExecutor(executor);

        LOGGER.info("Starting preparation phase");
        this.testConfig.createConfig();

        if (this.testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            clientTestPreparation();
        } else if (this.testConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
            serverTestPreparation();
        } else throw new RuntimeException("Invalid TestEndpointMode");

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

    // TODO tcp dump for every test?
    private void startTcpDump() {
        if (tcpdumpProcess != null) {
            LOGGER.warn("This should not happen...");
            return;
        }

        String networkInterface = testConfig.getAnvilTestConfig().getNetworkInterface();

        if (networkInterface.equals("any")) {
            LOGGER.warn(
                    "Tcpdump will capture on all interfaces. Use -networkInterface to reduce amount of collected data.");
        }

        ProcessBuilder tcpdump =
                new ProcessBuilder(
                        "tcpdump",
                        "-i",
                        networkInterface,
                        "-w",
                        Paths.get(testConfig.getAnvilTestConfig().getOutputFolder(), "dump.pcap")
                                .toString());

        try {
            tcpdumpProcess = tcpdump.start();
            boolean isFinished = tcpdumpProcess.waitFor(2, TimeUnit.SECONDS);
            if (!isFinished) throw new IllegalStateException();
            String out =
                    new String(
                            tcpdumpProcess.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            out +=
                    new String(
                            tcpdumpProcess.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            throw new RuntimeException(out);
        } catch (IllegalStateException ignored) {

        } catch (Exception e) {
            LOGGER.error("Starting tcpdump failed", e.getMessage());
        }
    }

    private void stopTcpDump() {
        if (tcpdumpProcess != null) {
            try {
                tcpdumpProcess.destroy();
            } catch (Exception ignored) {
            }
        }
    }

    private void logCommonDerivationValues() {
        LOGGER.info(
                "Supported NamedGroups:  "
                        + TestContext.getInstance()
                                .getFeatureExtractionResult()
                                .getNamedGroups()
                                .stream()
                                .map(NamedGroup::toString)
                                .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported CipherSuites: "
                        + TestContext.getInstance()
                                .getFeatureExtractionResult()
                                .getCipherSuites()
                                .stream()
                                .map(CipherSuite::toString)
                                .collect(Collectors.joining(",")));
        if (TestContext.getInstance().getFeatureExtractionResult().getTls13Groups() != null) {
            LOGGER.info(
                    "Supported TLS 1.3 NamedGroups: "
                            + TestContext.getInstance()
                                    .getFeatureExtractionResult()
                                    .getTls13Groups()
                                    .stream()
                                    .map(NamedGroup::toString)
                                    .collect(Collectors.joining(",")));
        }
        if (TestContext.getInstance().getFeatureExtractionResult().getSupportedTls13CipherSuites()
                != null) {
            LOGGER.info(
                    "Supported TLS 1.3 CipherSuites: "
                            + TestContext.getInstance()
                                    .getFeatureExtractionResult()
                                    .getSupportedTls13CipherSuites()
                                    .stream()
                                    .map(CipherSuite::toString)
                                    .collect(Collectors.joining(",")));
        }
    }

    /**
     * Ensures that the ClientScanner always uses the externally managed socket
     *
     * @return Function to set socket in created state
     */
    private Function<State, Integer> getSocketManagementCallback() {
        return (State state) -> {
            try {
                if (testConfig.isUseDTLS()) {
                    state.getTlsContext()
                            .setTransportHandler(
                                    new ServerUdpTransportHandler(
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getTestClientDelegate().getPort()));
                } else {
                    state.getTlsContext()
                            .setTransportHandler(
                                    new ServerTcpTransportHandler(
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getTestClientDelegate().getServerSocket()));
                }
                return 0;
            } catch (IOException ex) {
                LOGGER.error("Failed to set server socket", ex);
                return 1;
            }
        };
    }

    private static boolean countTests(TestIdentifier i, String versionS, String modeS) {
        TestSource source = i.getSource().orElse(null);
        if (!i.isTest() && (source == null || !source.getClass().equals(MethodSource.class))) {
            return false;
        }

        Set<TestTag> tags = i.getTags();
        boolean version = tags.stream().anyMatch(j -> j.getName().equals(versionS));
        boolean mode;
        if (!modeS.equals("both")) {
            mode = tags.stream().anyMatch(j -> j.getName().equals(modeS));
        } else {
            mode =
                    tags.stream().noneMatch(j -> j.getName().equals("server"))
                            && tags.stream().noneMatch(j -> j.getName().equals("client"));
        }

        return version && mode;
    }

    /**
     * Logs, how many tests were discovered for every TLS version, as well as test strength and
     * connection timeout.
     *
     * @param testPlan the testPlan, supplied by JUnits discovery
     */
    public static void printTestInfo(TestPlan testPlan) {
        long clientTls12 = testPlan.countTestIdentifiers(i -> countTests(i, "tls12", "client"));
        long clientTls13 = testPlan.countTestIdentifiers(i -> countTests(i, "tls13", "client"));
        long serverTls12 = testPlan.countTestIdentifiers(i -> countTests(i, "tls12", "server"));
        long serverTls13 = testPlan.countTestIdentifiers(i -> countTests(i, "tls13", "server"));
        long bothTls12 = testPlan.countTestIdentifiers(i -> countTests(i, "tls12", "both"));
        long bothTls13 = testPlan.countTestIdentifiers(i -> countTests(i, "tls13", "both"));

        LOGGER.info(
                "Server tests, TLS 1.2: {}, TLS 1.3: {}",
                serverTls12 + bothTls12,
                serverTls13 + bothTls13);
        LOGGER.info(
                "Client tests, TLS 1.2: {}, TLS 1.3: {}",
                clientTls12 + bothTls12,
                clientTls13 + bothTls13);
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
