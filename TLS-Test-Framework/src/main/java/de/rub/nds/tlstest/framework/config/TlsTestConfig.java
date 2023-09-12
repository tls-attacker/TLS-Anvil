/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.scanner.core.constants.CollectionResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.delegates.*;
import de.rub.nds.tlstest.framework.utils.Utils;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.NONE,
        setterVisibility = JsonAutoDetect.Visibility.NONE,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE)
public class TlsTestConfig extends TLSDelegateConfig {

    @JsonProperty private AnvilTestConfig anvilTestConfig;
    private static final Logger LOGGER = LogManager.getLogger();

    @JsonProperty("clientConfig")
    private TestClientDelegate testClientDelegate = null;

    @JsonProperty("serverConfig")
    private TestServerDelegate testServerDelegate = null;

    private TestExtractorDelegate testExtractorDelegate = null;
    private WorkerDelegate workerDelegate = null;

    private JCommander argParser = null;

    private TestEndpointType testEndpointMode = null;
    private boolean parsedArgs = false;

    private Config cachedConfig = null;
    private Callable<Integer> timeoutActionScript;

    private ConfigDelegates parsedCommand = null;

    @Parameter(
            names = "-exportTraces",
            description =
                    "Export executed WorkflowTraces with all values " + "used in the messages")
    private boolean exportTraces = false;

    // we might want to turn these into CLI parameters in the future
    private boolean expectTls13Alerts = false;
    private boolean enforceSenderRestrictions = false;

    public TlsTestConfig() {
        super(new GeneralDelegate());
        this.testServerDelegate = new TestServerDelegate();
        this.testClientDelegate = new TestClientDelegate();
        this.testExtractorDelegate = new TestExtractorDelegate();
        this.workerDelegate = new WorkerDelegate();
    }

    /**
     * This function parses the COMMAND environment variable which can be used as alternative to the
     * default arguments passed to the program. This is needed to be able to run TLS-Tests directly
     * from the IDE via GUI.
     *
     * @return arguments parsed from the COMMAND environment variable
     */
    @Nullable
    private String[] argsFromEnvironment() {
        String clientEnv = System.getenv("COMMAND_CLIENT");
        String serverEnv = System.getenv("COMMAND_SERVER");
        if (clientEnv == null && serverEnv == null) {
            throw new ParameterException("No args could be found");
        }
        if (testEndpointMode == null && clientEnv != null && serverEnv != null) {
            return null;
        }
        if (testEndpointMode == TestEndpointType.SERVER) {
            if (serverEnv == null) throw new ParameterException("SERVER_COMMAND is missing");
            clientEnv = null;
        }
        if (testEndpointMode == TestEndpointType.CLIENT) {
            if (clientEnv == null) throw new ParameterException("CLIENT_COMMAND is missing");
            serverEnv = null;
        }

        if (clientEnv != null) {
            return clientEnv.split("\\s");
        } else {
            return serverEnv.split("\\s");
        }
    }

    public void parse(@Nullable String[] args) {
        if (isParsedArgs()) return;
        anvilTestConfig = new AnvilTestConfig();

        if (argParser == null) {
            argParser =
                    JCommander.newBuilder()
                            .addCommand(ConfigDelegates.CLIENT.getCommand(), testClientDelegate)
                            .addCommand(ConfigDelegates.SERVER.getCommand(), testServerDelegate)
                            .addCommand(
                                    ConfigDelegates.EXTRACT_TESTS.getCommand(),
                                    testExtractorDelegate)
                            .addCommand(ConfigDelegates.WORKER.getCommand(), workerDelegate)
                            .addObject(getAnvilTestConfig())
                            .addObject(this)
                            .build();
        }

        if (args == null) {
            args = argsFromEnvironment();
            if (args == null) return;
        }

        this.argParser.parse(args);
        this.parsedCommand = ConfigDelegates.delegateForCommand(this.argParser.getParsedCommand());

        if (getGeneralDelegate().isHelp()) {
            argParser.usage();
            System.exit(0);
        } else if (argParser.getParsedCommand() == null) {
            argParser.usage();
            throw new ParameterException("You have to use the client or server command");
        } else if (argParser.getParsedCommand().equals(ConfigDelegates.EXTRACT_TESTS.getCommand())
                || argParser.getParsedCommand().equals(ConfigDelegates.WORKER.getCommand())) {
            return;
        }

        this.setTestEndpointMode(argParser.getParsedCommand());
        this.getAnvilTestConfig().setEndpointMode(this.getTestEndpointMode());

        if (getAnvilTestConfig().getIdentifier() == null) {
            if (argParser.getParsedCommand().equals(ConfigDelegates.SERVER.getCommand())) {
                getAnvilTestConfig().setIdentifier(testServerDelegate.getHost());
            } else {
                getAnvilTestConfig().setIdentifier(testClientDelegate.getPort().toString());
            }
        }

        if (getAnvilTestConfig().getOutputFolder().isEmpty()) {
            getAnvilTestConfig()
                    .setOutputFolder(
                            Paths.get(
                                            System.getProperty("user.dir"),
                                            "TestSuiteResults_"
                                                    + Utils.DateToISO8601UTC(new Date()))
                                    .toString());
        }

        try {
            Path outputFolder = Paths.get(getAnvilTestConfig().getOutputFolder());
            outputFolder = outputFolder.toAbsolutePath();
            outputFolder.toFile().mkdirs();
            getAnvilTestConfig().setOutputFolder(outputFolder.toString());

            if (!anvilTestConfig.getTimeoutActionCommand().isEmpty()) {
                timeoutActionScript =
                        () -> {
                            LOGGER.debug("Timeout action executed");
                            ProcessBuilder processBuilder =
                                    new ProcessBuilder(
                                            getAnvilTestConfig().getTimeoutActionCommand());
                            Process p = processBuilder.start();
                            p.waitFor();
                            Thread.sleep(1500);
                            return p.exitValue();
                        };
            }

            if (this.getGeneralDelegate().getKeylogfile() == null) {
                this.getGeneralDelegate()
                        .setKeylogfile(
                                Path.of(getAnvilTestConfig().getOutputFolder(), "keyfile.log")
                                        .toString());
            }
        } catch (Exception e) {
            throw new ParameterException(e);
        }
        parsedArgs = true;
    }

    public void fromWorker(AnvilTestConfig anvilConfig, String additionalConfig) {
        this.anvilTestConfig = anvilConfig;
        this.setTestEndpointMode(anvilConfig.getEndpointMode());
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        try {
            TlsTestConfig newConfig = mapper.readValue(additionalConfig, this.getClass());
            this.testClientDelegate = newConfig.testClientDelegate;
            this.testServerDelegate = newConfig.testServerDelegate;
            this.parsedArgs = true;
        } catch (JsonProcessingException e) {
            LOGGER.error("Error applying tls test config", e);
        }
    }

    @Override
    public synchronized Config createConfig() {
        if (cachedConfig != null) {
            Config config = cachedConfig.createCopy();
            FeatureExtractionResult report = TestContext.getInstance().getFeatureExtractionResult();
            if (report != null) {
                List<CipherSuite> supported = new ArrayList<>();
                if (TestContext.getInstance().getConfig().getTestEndpointMode()
                        == TestEndpointType.CLIENT) {
                    if (!report.getCipherSuites()
                            .contains(config.getDefaultSelectedCipherSuite())) {
                        supported.addAll(report.getCipherSuites());
                    }
                    config.setAddRenegotiationInfoExtension(checkRenegotiationInfoOffer());
                } else {
                    Optional<VersionSuiteListPair> suitePair =
                            report.getVersionSuitePairs().stream()
                                    .filter(i -> i.getVersion() == ProtocolVersion.TLS12)
                                    .findFirst();
                    if (suitePair.isPresent()
                            && !suitePair
                                    .get()
                                    .getCipherSuiteList()
                                    .contains(config.getDefaultSelectedCipherSuite())) {
                        supported.addAll(suitePair.get().getCipherSuiteList());
                    }
                }
                if (supported.size() > 0) {
                    if (supported.contains(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
                    } else if (supported.contains(
                            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
                    } else if (supported.contains(
                            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
                    } else if (supported.contains(
                            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
                    } else if (supported.contains(
                            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)) {
                        config.setDefaultSelectedCipherSuite(
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
                    } else {
                        config.setDefaultSelectedCipherSuite(supported.get(0));
                    }
                }
            }
            return config;
        }

        switch (this.testEndpointMode) {
            case CLIENT:
                addDelegate(this.testClientDelegate);
                break;
            case SERVER:
                addDelegate(this.testServerDelegate);
                break;
            default:
                throw new RuntimeException("Invalid testEndpointMode");
        }

        Config config = super.createConfig();
        config.setAddRenegotiationInfoExtension(checkRenegotiationInfoOffer());
        config.setChooserType(ChooserType.SMART_RECORD_SIZE);

        // Server test -> TLS-Attacker acts as Client
        config.getDefaultClientConnection()
                .setFirstTimeout(
                        (getAnvilTestConfig().getParallelTestCases() + 1)
                                * getAnvilTestConfig().getConnectionTimeout());
        config.getDefaultClientConnection().setTimeout(getAnvilTestConfig().getConnectionTimeout());
        config.getDefaultClientConnection().setConnectionTimeout(0);

        // Client test -> TLS-Attacker acts as Server
        config.getDefaultServerConnection()
                .setFirstTimeout(getAnvilTestConfig().getConnectionTimeout());
        config.getDefaultServerConnection().setTimeout(getAnvilTestConfig().getConnectionTimeout());

        config.setWorkflowExecutorShouldClose(true);
        config.setStealthMode(true);
        config.setRetryFailedClientTcpSocketInitialization(true);
        config.setReceiveFinalTcpSocketStateWithTimeout(true);
        config.setPreferredCertRsaKeySize(4096);
        config.setPreferredCertDssKeySize(3072);

        config.setFiltersKeepUserSettings(Boolean.FALSE);
        config.setDefaultProposedAlpnProtocols(
                "http/1.1",
                "spdy/1",
                "spdy/2",
                "spdy/3",
                "stun.turn",
                "stun.nat-discovery",
                "h2",
                "h2c",
                "webrtc",
                "c-webrtc",
                "ftp",
                "imap",
                "pop3",
                "managesieve");

        cachedConfig = config;
        return config;
    }

    public boolean checkRenegotiationInfoOffer() {
        if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT
                && TestContext.getInstance().getFeatureExtractionResult() != null) {
            ClientFeatureExtractionResult extractionResult =
                    (ClientFeatureExtractionResult)
                            TestContext.getInstance().getFeatureExtractionResult();
            if (!((CollectionResult)
                                    extractionResult.getResult(
                                            TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES))
                            .getCollection()
                            .contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
                    && !extractionResult
                            .getAdvertisedExtensions()
                            .contains(ExtensionType.RENEGOTIATION_INFO)) {
                return false;
            }
        }
        return true;
    }

    public synchronized Config createTls13Config() {
        Config config = this.createConfig();

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512,
                SignatureAndHashAlgorithm.RSA_SHA256,
                SignatureAndHashAlgorithm.RSA_SHA384,
                SignatureAndHashAlgorithm.RSA_SHA512,
                SignatureAndHashAlgorithm.ECDSA_SHA256,
                SignatureAndHashAlgorithm.ECDSA_SHA384,
                SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                config.getDefaultServerSupportedSignatureAndHashAlgorithms());

        config.setDefaultServerSupportedCipherSuites(
                CipherSuite.getImplemented().stream()
                        .filter(CipherSuite::isTLS13)
                        .collect(Collectors.toList()));
        config.setDefaultClientSupportedCipherSuites(
                config.getDefaultServerSupportedCipherSuites());
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultClientNamedGroups(
                Arrays.stream(NamedGroup.values())
                        .filter(NamedGroup::isTls13)
                        .collect(Collectors.toList()));
        config.setDefaultServerNamedGroups(config.getDefaultClientNamedGroups());
        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);

        config.setDefaultClientKeyShareNamedGroups(config.getDefaultClientNamedGroups());

        return config;
    }

    public TestEndpointType getTestEndpointMode() {
        return testEndpointMode;
    }

    public void setTestEndpointMode(TestEndpointType testEndpointMode) {
        this.testEndpointMode = testEndpointMode;
    }

    private void setTestEndpointMode(@Nonnull String testEndpointMode) {
        if (testEndpointMode.toLowerCase().equals(TestEndpointType.CLIENT.toString())) {
            this.testEndpointMode = TestEndpointType.CLIENT;
        } else if (testEndpointMode.toLowerCase().equals(TestEndpointType.SERVER.toString())) {
            this.testEndpointMode = TestEndpointType.SERVER;
        } else {
            throw new RuntimeException("Invalid testEndpointMode");
        }
    }

    public TestServerDelegate getTestServerDelegate() {
        return testServerDelegate;
    }

    public TestClientDelegate getTestClientDelegate() {
        return testClientDelegate;
    }

    public WorkerDelegate getWorkerDelegate() {
        return workerDelegate;
    }

    public void setArgParser(JCommander argParser) {
        if (isParsedArgs()) {
            LOGGER.warn(
                    "Args are already parsed, setting the argParse requires calling parse() again.");
        }
        this.argParser = argParser;
    }

    public JCommander getArgParser() {
        return argParser;
    }

    public boolean isExpectTls13Alerts() {
        return expectTls13Alerts;
    }

    public void setExpectTls13Alerts(boolean expectTls13Alerts) {
        this.expectTls13Alerts = expectTls13Alerts;
    }

    public boolean isEnforceSenderRestrictions() {
        return enforceSenderRestrictions;
    }

    public boolean isExportTraces() {
        return exportTraces;
    }

    public void setExportTraces(boolean exportTraces) {
        this.exportTraces = exportTraces;
    }

    public ConfigDelegates getParsedCommand() {
        return parsedCommand;
    }

    public TestExtractorDelegate getTestExtractorDelegate() {
        return testExtractorDelegate;
    }

    public boolean isParsedArgs() {
        return parsedArgs;
    }

    public AnvilTestConfig getAnvilTestConfig() {
        return anvilTestConfig;
    }

    public Callable<Integer> getTimeoutActionScript() {
        return timeoutActionScript;
    }
}
