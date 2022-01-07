/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.utils.Utils;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.stream.Collectors;


public class TestConfig extends TLSDelegateConfig {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestClientDelegate testClientDelegate = null;
    private TestServerDelegate testServerDelegate = null;

    private JCommander argParser = null;

    private TestEndpointType testEndpointMode = null;
    private boolean parsedArgs = false;

    private Config cachedConfig = null;
    private List<ProtocolVersion> supportedVersions = null;
    private Callable<Integer> timeoutActionScript;


    @Parameter(names = "-tags", description = "Run only tests containing on of the specified tags")
    private List<String> tags = new ArrayList<>();

    @Parameter(names = "-testPackage", description = "Run only tests included in the specified package")
    private String testPackage = null;

    @Parameter(names = "-ignoreCache", description = "Discovering supported TLS-Features takes time, " +
            "thus they are cached. Using this flag, the cache is ignored.")
    private boolean ignoreCache = false;
    
    @Parameter(names = "-exportTraces", description = "Export executed WorkflowTraces with all values "
            + "used in the messages")
    private boolean exportTraces = false;

    @Parameter(names = "-outputFolder", description = "Folder where the test results should be stored inside, defaults to `pwd/TestSuiteResults_$(date)`")
    private String outputFolder = "";

    @Parameter(names = "-parallelHandshakes", description = "How many TLS-Handshakes should be executed in parallel? (Default value: 5)")
    private int parallelHandshakes = 5;

    @Parameter(names = "-parallelTests", description = "How many tests should be executed in parallel? (Default value: parallelHandshakes * 1.5)")
    private Integer parallelTests = null;
    
    @Parameter(names = "-restartServerAfter", description = "How many handshakes should be executed for a Server before a restart? (Default value: 0 = infinite)")
    private Integer restartServerAfter = 0;

    @Parameter(names = "-timeoutActionScript", description = "Script to execute, if the execution of the testsuite " +
            "seems to make no progress", variableArity = true)
    private List<String> timeoutActionCommand = new ArrayList<>();

    @Parameter(names = "-identifier", description = "Identifier that is visible in the serialized test result. " +
            "Defaults to the hostname of the target or the port. The identifier is visible in the test report.")
    private String identifier = null;

    @Parameter(names = "-strength", description = "Strength of the pairwise test. (Default value: 4)")
    private int strength = 4;
    
    @Parameter(names = "-connectionTimeout", description = "The default timeout for TLS sessions in ms. (Default value: 1000)")
    private int connectionTimeout = 1000;

    @Parameter(names = "-prettyPrintJSON", description = "Pretty print json output")
    private boolean prettyPrintJSON = false;

    // -- Extensions --
    @Parameter(names = "-configOptionsConfigFile", description = "Defines the path of the configuration option config file to enable configuration option tests.")
    private String configOptionsConfigFile = "";

    
    //we might want to turn these into CLI parameters in the future
    private boolean expectTls13Alerts = false;
    private boolean enforceSenderRestrictions = false;
    
    public TestConfig() {
        super(new GeneralDelegate());
        this.testServerDelegate = new TestServerDelegate();
        this.testClientDelegate = new TestClientDelegate();
    }


    /**
     * This function parses the COMMAND environment variable which can be used
     * as alternative to the default arguments passed to the program.
     * This is needed to be able to run TLS-Tests directly from the IDE via GUI.
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
            if (serverEnv == null)
                throw new ParameterException("SERVER_COMMAND is missing");
            clientEnv = null;
        }
        if (testEndpointMode == TestEndpointType.CLIENT) {
            if (clientEnv == null)
                throw new ParameterException("CLIENT_COMMAND is missing");
            serverEnv = null;
        }

        if (clientEnv != null) {
            return clientEnv.split("\\s");
        } else {
            return serverEnv.split("\\s");
        }
    }


    public void parse(@Nullable String[] args) {
        if (parsedArgs)
            return;

        if (argParser == null) {
            argParser = JCommander.newBuilder()
                    .addCommand("client", testClientDelegate)
                    .addCommand("server", testServerDelegate)
                    .addObject(this)
                    .build();
        }

        if (args == null) {
            args = argsFromEnvironment();
            if (args == null)
                return;
        }

        this.argParser.parse(args);
        if (argParser.getParsedCommand() == null) {
            argParser.usage();
            throw new ParameterException("You have to use the client or server command");
        }

        this.setTestEndpointMode(argParser.getParsedCommand());

        if (getGeneralDelegate().isHelp()) {
            argParser.usage();
        }

        if (this.identifier == null) {
            if (argParser.getParsedCommand().equals("server")) {
                this.identifier = testServerDelegate.getHost();
            }
            else {
                this.identifier = testClientDelegate.getPort().toString();
            }
        }

        if (this.outputFolder.isEmpty()) {
            this.outputFolder = Paths.get(System.getProperty("user.dir"), "TestSuiteResults_" + Utils.DateToISO8601UTC(new Date())).toString();
        }

        try {
            Path outputFolder = Paths.get(this.outputFolder);
            outputFolder = outputFolder.toAbsolutePath();

            this.outputFolder = outputFolder.toString();

            if (timeoutActionCommand.size() > 0) {
                timeoutActionScript = () -> {
                        LOGGER.debug("Timeout action executed");
                        ProcessBuilder processBuilder = new ProcessBuilder(timeoutActionCommand);
                        Process p = processBuilder.start();
                        p.waitFor();
                        Thread.sleep(1500);
                        return p.exitValue();
                };
            }
        } catch (Exception e) {
            throw new ParameterException(e);
        }

        parallelHandshakes = Math.min(parallelHandshakes, Runtime.getRuntime().availableProcessors());
        if (parallelTests == null) {
            parallelTests = (int)Math.ceil(parallelHandshakes * 1.5);
        }

        parsedArgs = true;
    }

    synchronized  public void clearConfigCache(){
        cachedConfig = null;
    }

    @Override
    synchronized public Config createConfig() {
        if (cachedConfig != null) {
            Config config = cachedConfig.createCopy();
            TestSiteReport report = TestContext.getInstance().getSiteReport();
            if (report != null) {
                List<CipherSuite> supported = new ArrayList<>();
                if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
                    if (!report.getCipherSuites().contains(config.getDefaultSelectedCipherSuite())) {
                        supported.addAll(report.getCipherSuites());
                    }
                } else {
                    Optional<VersionSuiteListPair> suitePair = report.getVersionSuitePairs().stream().filter(i -> i.getVersion() == ProtocolVersion.TLS12).findFirst();
                    if (suitePair.isPresent() && !suitePair.get().getCipherSuiteList().contains(config.getDefaultSelectedCipherSuite())) {
                        supported.addAll(suitePair.get().getCipherSuiteList());
                    }
                }
                if (supported.size() > 0) {
                    if (supported.contains(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
                    } else if (supported.contains(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
                    } else if (supported.contains(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)) {
                        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
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

        // Server test -> TLS-Attacker acts as Client
        config.getDefaultClientConnection().setFirstTimeout((parallelHandshakes + 1) * connectionTimeout);
        config.getDefaultClientConnection().setTimeout(connectionTimeout);
        config.getDefaultClientConnection().setConnectionTimeout(0);


        // Client test -> TLS-Attacker acts as Server
        config.getDefaultServerConnection().setFirstTimeout(connectionTimeout);
        config.getDefaultServerConnection().setTimeout(connectionTimeout);


        config.setWorkflowExecutorShouldClose(true);
        config.setEarlyStop(false);
        config.setStealthMode(true);
        config.setRetryFailedClientTcpSocketInitialization(true);
        config.setReceiveFinalTcpSocketStateWithTimeout(true);
        config.setPrefferedCertRsaKeySize(4096);
        config.setPrefferedCertDssKeySize(3072);
        
        config.setFiltersKeepUserSettings(Boolean.FALSE);
        config.setDefaultProposedAlpnProtocols("http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn",
                "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve");

        cachedConfig = config;
        return config;
    }

    synchronized public Config createTls13Config() {
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
                SignatureAndHashAlgorithm.ECDSA_SHA512
        );
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(config.getDefaultServerSupportedSignatureAndHashAlgorithms());

        config.setDefaultServerSupportedCipherSuites(CipherSuite.getImplemented().stream().filter(CipherSuite::isTLS13).collect(Collectors.toList()));
        config.setDefaultClientSupportedCipherSuites(config.getDefaultServerSupportedCipherSuites());
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultClientNamedGroups(Arrays.stream(NamedGroup.values()).filter(NamedGroup::isTls13).collect(Collectors.toList()));
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

    public String getTestPackage() {
        return testPackage;
    }

    public List<String> getTags() {
        return tags;
    }

    public TestServerDelegate getTestServerDelegate() {
        return testServerDelegate;
    }

    public TestClientDelegate getTestClientDelegate() {
        return testClientDelegate;
    }

    public void setArgParser(JCommander argParser) {
        if (parsedArgs) {
            LOGGER.warn("Args are already parsed, setting the argParse requires calling parse() again.");
        }
        this.argParser = argParser;
    }

    public JCommander getArgParser() {
        return argParser;
    }

    public boolean isIgnoreCache() {
        return ignoreCache;
    }

    public void setIgnoreCache(boolean ignoreCache) {
        this.ignoreCache = ignoreCache;
    }

    public String getOutputFolder() {
        return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolder = outputFolder;
    }

    public boolean isParsedArgs() {
        return parsedArgs;
    }

    public int getParallelHandshakes() {
        return parallelHandshakes;
    }

    public void setParallelHandshakes(int parallelHandshakes) {
        this.parallelHandshakes = parallelHandshakes;
    }

    public List<ProtocolVersion> getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(List<ProtocolVersion> supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public void setSupportedVersions(ProtocolVersion ...supportedVersions) {
        this.supportedVersions = Arrays.asList(supportedVersions);
    }

    public Callable<Integer> getTimeoutActionScript() {
        return timeoutActionScript;
    }

    public void setTimeoutActionScript(Callable<Integer> timeoutActionScript) {
        this.timeoutActionScript = timeoutActionScript;
    }

    public List<String> getTimeoutActionCommand() {
        return timeoutActionCommand;
    }

    public void setTimeoutActionCommand(List<String> timeoutActionCommand) {
        this.timeoutActionCommand = timeoutActionCommand;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public int getParallelTests() {
        return parallelTests;
    }

    public void setParallelTests(int parallelTests) {
        this.parallelTests = parallelTests;
    }

    public int getStrength() {
        return strength;
    }

    public void setStrength(int strength) {
        this.strength = strength;
    }

    public Integer getRestartServerAfter() {
        return restartServerAfter;
    }

    public void setRestartServerAfter(Integer restartServerAfter) {
        this.restartServerAfter = restartServerAfter;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
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

    public boolean isPrettyPrintJSON() {
        return prettyPrintJSON;
    }

    public void setPrettyPrintJSON(boolean prettyPrintJSON) {
        this.prettyPrintJSON = prettyPrintJSON;
    }

    public String getConfigOptionsConfigFile(){
        return this.configOptionsConfigFile;
    }

    public void setConfigOptionsConfigFile(String configOptionsConfigFile){
        this.configOptionsConfigFile = configOptionsConfigFile;
    }

}
