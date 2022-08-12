/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsscanner.serverscanner.ConsoleLogger;
import de.rub.nds.tlsscanner.serverscanner.TlsScanner;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.filter.ThresholdFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Helper class to create TestSiteReports. This code is basically a copy of the code in TestRunner, but since it is does
 * not provide an interface for TestSiteReports (and is not responsible for that) we copied it. Maybe we can use this
 * factory to build the TestRunner's SiteReports in the future.
 */
public class TestSiteReportFactory {
    private static final Logger LOGGER = LogManager.getLogger(TestSiteReportFactory.class);
    private static boolean targetIsReady = false;

    public static TestSiteReport createServerSiteReport(String hostName, Integer port, boolean disableConsoleLog) {

        Filter noInfoAndWarningsFilter = ThresholdFilter.createFilter( Level.ERROR, Filter.Result.ACCEPT, Filter.Result.DENY );
        if(disableConsoleLog){
            applyFilterOnLogger(ConsoleLogger.CONSOLE, noInfoAndWarningsFilter);
        }

        TestConfig testConfig = new TestConfig();
        testConfig.setTestEndpointMode(TestEndpointType.SERVER);

        testConfig.getTestServerDelegate().setHost(hostName+":"+port);

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

        if(disableConsoleLog){
            removeFilterFromLogger(noInfoAndWarningsFilter);
        }
        return report;
    }

    public static TestSiteReport createClientSiteReport(TestConfig testConfig, InboundConnection inboundConnection,  boolean disableConsoleLog) {
        Filter noInfoAndWarningsFilter = ThresholdFilter.createFilter( Level.ERROR, Filter.Result.ACCEPT, Filter.Result.DENY );
        if(disableConsoleLog){
            applyFilterOnLogger(LOGGER, noInfoAndWarningsFilter);
        }

        List<TlsTask> tasks = new ArrayList<>();
        List<State> states = new ArrayList<>();

        List<CipherSuite> cipherList = CipherSuite.getImplemented();


        for (CipherSuite i: cipherList) {
            Config config = testConfig.createConfig();
            if (i.isTLS13()) {
                config = testConfig.createTls13Config();
            }

            if(inboundConnection != null){
                config.setDefaultServerConnection(inboundConnection);
            }


            config.setDefaultServerSupportedCipherSuites(Collections.singletonList(i));
            config.setDefaultSelectedCipherSuite(i);
            config.setEnforceSettings(true);

            //waitForClient(testConfig, config);

            try {
                WorkflowConfigurationFactory configurationFactory = new WorkflowConfigurationFactory(config);
                WorkflowTrace trace = configurationFactory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
                State state = new State(config, trace);
                prepareStateForConnection(state, testConfig);
                StateExecutionTask task = new StateExecutionTask(state, 2);
                task.setBeforeTransportInitCallback(testConfig.getTestClientDelegate().getTriggerScript());
                tasks.add(task);
                states.add(state);
            }
            catch(Exception ignored) {

            }
        }

        ParallelExecutor executor = new ParallelExecutor(testConfig.getParallelHandshakes(), 2);
        LOGGER.info("Executing client exploration with {} parallel threads...", testConfig.getParallelHandshakes());
        executor.bulkExecuteTasks(tasks);


        Set<CipherSuite> tls12CipherSuites = new HashSet<>();
        Set<CipherSuite> tls13CipherSuites = new HashSet<>();
        ClientHelloMessage clientHello = null;
        ReceiveAction clientHelloReceiveAction = null;
        long failed = 0;
        for (State s: states) {
            try {
                //allow additional app data sent by tls 1.3 client
                if(s.getConfig().getDefaultSelectedCipherSuite().isTLS13()) {
                    ReceiveAction lastReceive = (ReceiveAction)s.getWorkflowTrace().getReceivingActions().get(s.getWorkflowTrace().getReceivingActions().size() -1 );
                    ApplicationMessage appMsg = new ApplicationMessage();
                    appMsg.setRequired(false);
                    lastReceive.getExpectedMessages().add(appMsg);
                }
                if (s.getWorkflowTrace().executedAsPlanned()) {
                    if (clientHello == null) {
                        clientHello = s.getWorkflowTrace().getFirstReceivedMessage(ClientHelloMessage.class);
                        clientHelloReceiveAction = (ReceiveAction)s.getWorkflowTrace().getReceivingActions().get(0);
                    }
                    if (s.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS12)
                        tls12CipherSuites.add(s.getConfig().getDefaultSelectedCipherSuite());
                    else if (s.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13)
                        tls13CipherSuites.add(s.getConfig().getDefaultSelectedCipherSuite());
                }
                else {
                    failed++;
                    LOGGER.debug("Workflow failed (" + s.getConfig().getDefaultSelectedCipherSuite() + ")");
                }
            } catch (Exception e) {
                LOGGER.error(e);
                if(disableConsoleLog){
                    removeFilterFromLogger(noInfoAndWarningsFilter);
                }
                throw new RuntimeException(e);
            }
        }

        List<State> keyShareStates = new LinkedList<>();
        List<TlsTask> keyShareTasks = new LinkedList<>();
        assert clientHello != null;
        if(clientHello.containsExtension(ExtensionType.ELLIPTIC_CURVES) && clientHello.containsExtension(ExtensionType.KEY_SHARE)) {
            keyShareStates = buildClientKeyShareProbeStates(clientHello, testConfig, inboundConnection);
            if(!keyShareStates.isEmpty()) {
                for(State state: keyShareStates) {
                    StateExecutionTask task = new StateExecutionTask(state, 2);
                    try {
                        TestCOMultiClientDelegate delegate =  (TestCOMultiClientDelegate)testConfig.getTestClientDelegate();
                        state.getTlsContext().setTransportHandler(new ServerTcpTransportHandler(testConfig.getConnectionTimeout(), testConfig.getConnectionTimeout(), delegate.getServerSocket(state.getConfig())));
                    } catch (IOException ex) {
                        if(disableConsoleLog){
                            removeFilterFromLogger(noInfoAndWarningsFilter);
                        }
                        throw new RuntimeException("Failed to set TransportHandler");
                    }
                    state.getTlsContext().setRecordLayer(
                            RecordLayerFactory.getRecordLayer(state.getTlsContext().getRecordLayerType(), state.getTlsContext()));
                    task.setBeforeTransportInitCallback(testConfig.getTestClientDelegate().getTriggerScript());
                    keyShareTasks.add(task);
                }
                executor.bulkExecuteTasks(keyShareTasks);
            }
        }
        List<NamedGroup> additionalTls13Groups = new LinkedList<>();
        for(State state: keyShareStates) {
            try {
                //test for Finished instead of asPlanned(), to ignore legacy CCS
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
                    additionalTls13Groups.add(state.getConfig().getDefaultSelectedNamedGroup());
                }
                else {
                    failed++;
                    LOGGER.debug("Workflow failed (" + state.getConfig().getDefaultSelectedNamedGroup() + ")");
                }
            } catch (Exception e) {
                LOGGER.error(e);
                if(disableConsoleLog){
                    removeFilterFromLogger(noInfoAndWarningsFilter);
                }
                throw new RuntimeException(e);
            }
        }

        LOGGER.info(String.format("%d/%d client preparation workflows failed.", failed, states.size()));
        if (failed == states.size()) {
            if(disableConsoleLog){
                removeFilterFromLogger(noInfoAndWarningsFilter);
            }
            throw new RuntimeException("Client preparation could not be completed.");
        }

        int rsaMinCertKeySize = getCertMinimumKeySize(executor, tls12CipherSuites, CertificateKeyType.RSA, testConfig, inboundConnection);
        int dssMinCertKeySize = getCertMinimumKeySize(executor, tls12CipherSuites, CertificateKeyType.DSS, testConfig, inboundConnection);
        boolean supportsRecordFragmentation = clientSupportsRecordFragmentation(executor, tls12CipherSuites, tls13CipherSuites, testConfig, inboundConnection);

        TestSiteReport report = new TestSiteReport("");
        report.addCipherSuites(tls12CipherSuites);
        report.addCipherSuites(tls13CipherSuites);
        report.setReceivedClientHello(clientHello);
        report.putResult(AnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supportsRecordFragmentation);
        report.setMinimumRsaCertKeySize(rsaMinCertKeySize);
        report.setMinimumDssCertKeySize(dssMinCertKeySize);
        additionalTls13Groups.addAll(report.getClientHelloKeyShareGroups());
        report.setSupportedTls13Groups(additionalTls13Groups);

        EllipticCurvesExtensionMessage ecExt = clientHello.getExtension(EllipticCurvesExtensionMessage.class);
        if (ecExt != null) {
            report.setSupportedNamedGroups(
                    NamedGroup.namedGroupsFromByteArray(ecExt.getSupportedGroups().getValue())
                            .stream()
                            .filter(i -> NamedGroup.getImplemented().contains(i))
                            .collect(Collectors.toList())
            );
        }

        SupportedVersionsExtensionMessage supportedVersionsExt = clientHello.getExtension(SupportedVersionsExtensionMessage.class);
        List<ProtocolVersion> versions = new ArrayList<>();
        versions.add(ProtocolVersion.getProtocolVersion(clientHello.getProtocolVersion().getValue()));
        versions.add(ProtocolVersion.getProtocolVersion(((Record)clientHelloReceiveAction.getReceivedRecords().get(0)).getProtocolVersion().getValue()));
        if (supportedVersionsExt != null) {
            versions.addAll(ProtocolVersion.getProtocolVersions(supportedVersionsExt.getSupportedVersions().getValue()));
        }
        report.setVersions(new ArrayList<>(new HashSet<>(versions)));

        SignatureAndHashAlgorithmsExtensionMessage sahExt = clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        if (sahExt != null) {
            report.setSupportedSignatureAndHashAlgorithmsSke(
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(sahExt.getSignatureAndHashAlgorithms().getValue()).stream()
                            .filter(i -> SignatureAndHashAlgorithm.getImplemented().contains(i))
                            .collect(Collectors.toList())
            );
        }

        List<ExtensionType> extensions = clientHello.getExtensions().stream()
                .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                .collect(Collectors.toList());
        report.setSupportedExtensions(extensions);

        TestContext.getInstance().setReceivedClientHelloMessage(clientHello);
        //testContext.setSiteReport(report);
        executor.shutdown();

        if(disableConsoleLog){
            removeFilterFromLogger(noInfoAndWarningsFilter);
        }

        return report;

    }

    private static void waitForClient(TestConfig testConfig, Config config) {
        targetIsReady = false;
        try {
            new Thread(() -> {
                while (!targetIsReady) {
                    LOGGER.warn("Waiting for the client to get ready...");
                    try {
                        State state = new State();
                        TestCOMultiClientDelegate delegate =  (TestCOMultiClientDelegate)testConfig.getTestClientDelegate();
                        testConfig.getTestClientDelegate().executeTriggerScript(state);
                    } catch (Exception ignored) {}

                    try {
                        Thread.sleep(1000);
                    } catch (Exception ignored) {}
                }
            }).start();

            TestCOMultiClientDelegate delegate =  (TestCOMultiClientDelegate)testConfig.getTestClientDelegate();

            delegate.getServerSocket(config).accept();
            targetIsReady = true;
        } catch (Exception ignored) { }

        LOGGER.info("Client is ready, prepapring client exploration...");
    }

    private static void prepareStateForConnection(State state, TestConfig testConfig) {
        try {
            TestCOMultiClientDelegate delegate =  (TestCOMultiClientDelegate)testConfig.getTestClientDelegate();
            state.getTlsContext().setTransportHandler(new ServerTcpTransportHandler(testConfig.getConnectionTimeout(), testConfig.getConnectionTimeout(), delegate.getServerSocket(state.getConfig())));
            state.getTlsContext().setRecordLayer(
                    RecordLayerFactory.getRecordLayer(state.getTlsContext().getRecordLayerType(), state.getTlsContext()));
        } catch (IOException ex) {
            throw new RuntimeException("Failed to set TransportHandlers");
        }
    }

    private static List<State> buildClientKeyShareProbeStates(ClientHelloMessage clientHello, TestConfig testConfig, InboundConnection inboundConnection) {
        List<State> states = new ArrayList<>();
        EllipticCurvesExtensionMessage ecExtension = clientHello.getExtension(EllipticCurvesExtensionMessage.class);
        KeyShareExtensionMessage ksExtension = clientHello.getExtension(KeyShareExtensionMessage.class);
        List<NamedGroup> nonKeyShareCurves = NamedGroup.namedGroupsFromByteArray(ecExtension.getSupportedGroups().getValue());
        ksExtension.getKeyShareList().forEach(offeredKs -> nonKeyShareCurves.remove(offeredKs.getGroupConfig()));
        for (NamedGroup group: nonKeyShareCurves) {
            if (NamedGroup.getImplemented().contains(group)) {
                Config config = testConfig.createTls13Config();
                if(inboundConnection != null){
                    config.setDefaultServerConnection(inboundConnection);
                }
                config.setDefaultServerNamedGroups(group);
                config.setDefaultSelectedNamedGroup(group);
                try {
                    WorkflowConfigurationFactory configurationFactory = new WorkflowConfigurationFactory(config);
                    WorkflowTrace trace = configurationFactory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);

                    ClientHelloMessage failingClientHello = new ClientHelloMessage();
                    ServerHelloMessage helloRetryRequest = new ServerHelloMessage(config);
                    helloRetryRequest.setRandom(Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));

                    trace.getTlsActions().add(0, new SendAction(helloRetryRequest));
                    trace.getTlsActions().add(0, new ReceiveAction(failingClientHello));

                    State s = new State(config, trace);
                    states.add(s);
                }
                catch(Exception ignored) {

                }
            }
        }
        return states;
    }

    private static int getCertMinimumKeySize(ParallelExecutor executor, Set<CipherSuite> cipherSuites, CertificateKeyType keyType, TestConfig testConfig, InboundConnection inboundConnection) {
        List<CipherSuite> matchingCipherSuites = cipherSuites.stream().filter(cipherSuite -> AlgorithmResolver.getCertificateKeyType(cipherSuite) == keyType).collect(Collectors.toList());
        int minimumKeySize = 0;
        if(matchingCipherSuites.size() > 0) {
            List<State> certStates = getClientCertMinimumKeyLengthStates(matchingCipherSuites, keyType, testConfig, inboundConnection);
            List<TlsTask> certTasks = buildStateExecutionServerTasksFromStates(certStates, testConfig);
            executor.bulkExecuteTasks(certTasks);
            for(State executedState: certStates) {
                int certKeySize = executedState.getConfig().getDefaultExplicitCertificateKeyPair().getPublicKey().keySize();
                if(executedState.getWorkflowTrace().executedAsPlanned() && (certKeySize < minimumKeySize || minimumKeySize == 0)) {
                    minimumKeySize = certKeySize;
                }
            }
        }
        return minimumKeySize;
    }

    private static List<State> getClientCertMinimumKeyLengthStates(List<CipherSuite> supportedCipherSuites, CertificateKeyType keyType, TestConfig testConfig, InboundConnection inboundConnection) {
        Set<CertificateKeyPair> availableCerts = new HashSet<>();
        CertificateByteChooser.getInstance().getCertificateKeyPairList().forEach(certKeyPair -> {
            if(certKeyPair.getCertPublicKeyType() == keyType) {
                availableCerts.add(certKeyPair);
            }
        });

        List<State> testStates = new LinkedList<>();
        for(CertificateKeyPair certKeyPair: availableCerts) {
            Config config = testConfig.createConfig();
            if(inboundConnection != null){
                config.setDefaultServerConnection(inboundConnection);
            }
            config.setAutoSelectCertificate(false);
            config.setDefaultExplicitCertificateKeyPair(certKeyPair);
            config.setDefaultServerSupportedCipherSuites(supportedCipherSuites);
            config.setDefaultSelectedCipherSuite(supportedCipherSuites.get(0));
            State state = new State(config, new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER));
            testStates.add(state);
        }
        return testStates;
    }

    private static List<TlsTask> buildStateExecutionServerTasksFromStates(List<State> states, TestConfig testConfig) {
        List<TlsTask> testTasks = new LinkedList<>();
        states.forEach(state -> {
            prepareStateForConnection(state, testConfig);
            StateExecutionTask task = new StateExecutionTask(state, 2);
            task.setBeforeTransportInitCallback(testConfig.getTestClientDelegate().getTriggerScript());
            testTasks.add(task);
        });
        return testTasks;
    }

    private static boolean clientSupportsRecordFragmentation(ParallelExecutor executor, Set<CipherSuite> tls12CipherSuites, Set<CipherSuite> tls13CipherSuites, TestConfig testConfig, InboundConnection inboundConnection) {
        Config config = getServerConfigBasedOnCipherSuites(tls12CipherSuites, tls13CipherSuites, testConfig, inboundConnection);
        config.setDefaultMaxRecordData(50);

        State state = new State(config, new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER));
        prepareStateForConnection(state, testConfig);
        StateExecutionTask task = new StateExecutionTask(state, 2);
        task.setBeforeTransportInitCallback(testConfig.getTestClientDelegate().getTriggerScript());
        executor.bulkExecuteTasks(task);
        return state.getWorkflowTrace().executedAsPlanned();
    }

    private static Config getServerConfigBasedOnCipherSuites(Set<CipherSuite> tls12CipherSuites, Set<CipherSuite> tls13CipherSuites, TestConfig testConfig, InboundConnection inboundConnection) {
        Config config;
        CipherSuite suite;
        if(!tls12CipherSuites.isEmpty()) {
            config = testConfig.createConfig();
            suite = tls12CipherSuites.iterator().next();
        } else if(!tls13CipherSuites.isEmpty()) {
            config = testConfig.createTls13Config();
            suite = tls13CipherSuites.iterator().next();
        } else {
            throw new RuntimeException("No cipher suites detected");
        }
        if(inboundConnection != null){
            config.setDefaultServerConnection(inboundConnection);
        }
        config.setDefaultServerSupportedCipherSuites(suite);
        config.setDefaultSelectedCipherSuite(suite);
        return config;
    }

    private static void applyFilterOnLogger(Logger logger, Filter filter){
        org.apache.logging.log4j.core.Logger coreLogger = (org.apache.logging.log4j.core.Logger) logger;
        final LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        final Configuration config = ctx.getConfiguration();

        config.addLoggerFilter(coreLogger, filter);
    }
    private static void removeFilterFromLogger(Filter filter){
        final LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        final Configuration config = ctx.getConfiguration();

        config.getLoggerConfig(ConsoleLogger.CONSOLE.getName()).removeFilter(filter);
    }

}
