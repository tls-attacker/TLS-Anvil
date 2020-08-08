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
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
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


    @Parameter(names = "-tags", description = "Run only tests containing on of the specified tags", variableArity = true)
    private List<String> tags = new ArrayList<>();

    @Parameter(names = "-testPackage", description = "Run only tests included in the specified package")
    private String testPackage = null;

    @Parameter(names = "-ignoreCache", description = "Discovering supported TLS-Features takes time, thus they are cached. Using this flag, the cache is ignored.")
    private boolean ignoreCache = false;

    @Parameter(names = "-outputFile", description = "Filepath where the test results should be store, defaults to `pwd/results.json`")
    private String outputFile = "";

    @Parameter(names = "-outputFormat", description = "Defines the format of the output. Supported: xml or json")
    private String outputFormat = "";

    @Parameter(names = "-parallel", description = "How many TLS-Handshakes should be executed in parallel? (Default value: 5)")
    private int parallel = 5;

    @Parameter(names = "-timeoutActionScript", description = "Script to execute, if the execution of the testsuite seems to make no progress", variableArity = true)
    private List<String> timeoutActionCommand = new ArrayList<>();

    @Parameter(names = "-identifier", description = "Identifier that is visible in the serialized test result. Defaults to the ")
    private String identifier = null;


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
                    .addObject(this.getGeneralDelegate())
                    .build();
        }

        if (args == null) {
            args = argsFromEnvironment();
            if (args == null)
                return;
        }

        this.argParser.parse(args);
        if (argParser.getParsedCommand() == null) {
            throw new ParameterException("You have to use the client or server command");
        }

        this.setTestEndpointMode(argParser.getParsedCommand());

        if (getGeneralDelegate().isHelp()) {
            argParser.usage();
        }

        if (!this.outputFormat.equals("json") && !this.outputFormat.equals("xml") && !this.outputFormat.isEmpty()) {
            throw new ParameterException("-outputFormat must be 'json' or 'xml'");
        }

        String ext = "json";
        if (!this.outputFormat.isEmpty()) {
            ext = this.outputFormat;
        }

        if (this.identifier == null) {
            if (argParser.getParsedCommand().equals("server")) {
                this.identifier = testServerDelegate.getHost();
            }
            else {
                this.identifier = testClientDelegate.getPort().toString();
            }
        }

        if (this.outputFile.isEmpty()) {
            this.outputFile = Paths.get(System.getProperty("user.dir"), "testResults." + ext).toString();
        }

        try {
            Path outputFile = Paths.get(this.outputFile);
            if (this.outputFile.endsWith("/") || this.outputFile.endsWith("\\")) {
                outputFile = Paths.get(this.outputFile, "testResults." + ext);
            }

            outputFile = outputFile.toAbsolutePath();

            this.outputFile = outputFile.toString();
            if (!this.outputFile.endsWith(".xml") && !this.outputFile.endsWith(".json")) {
                throw new ParameterException("Invalid outputFile, only 'json' and 'xml' files are supported");
            }

            if (this.outputFormat.isEmpty()) {
                this.outputFormat = "json";
                if (this.outputFile.endsWith("xml")) {
                    this.outputFormat = "xml";
                }
            } else {
                if ((this.outputFile.endsWith(".xml") && this.outputFormat.equals("json")) ||
                        (this.outputFile.endsWith(".json") && this.outputFormat.equals("xml"))) {
                    throw new ParameterException("-outputFile file extension does not match -outputFormat");
                }
            }

            if (timeoutActionCommand.size() > 0) {
                timeoutActionScript = () -> {
                    LOGGER.debug("Timeout action executed");
                    ProcessBuilder processBuilder = new ProcessBuilder(timeoutActionCommand);
                    Process p = processBuilder.start();
                    p.waitFor();
                    return p.exitValue();
                };
            }
        } catch (Exception e) {
            throw new ParameterException(e);
        }

        parsedArgs = true;
    }


    @Override
    synchronized public Config createConfig() {
        if (cachedConfig != null) {
            return cachedConfig.createCopy();
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
        config.getDefaultClientConnection().setFirstTimeout((parallel + 1) * 1000);
        config.getDefaultClientConnection().setTimeout(1000);
        config.getDefaultClientConnection().setConnectionTimeout(0);


        // Client test -> TLS-Attacker acts as Server
        config.getDefaultServerConnection().setFirstTimeout(1000);
        config.getDefaultServerConnection().setTimeout(1000);


        config.setWorkflowExecutorShouldClose(true);
        config.setEarlyStop(true);
        config.setStealthMode(true);

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
                SignatureAndHashAlgorithm.ED25519,
                SignatureAndHashAlgorithm.ECDSA_SHA256,
                SignatureAndHashAlgorithm.ECDSA_SHA384,
                SignatureAndHashAlgorithm.ECDSA_SHA512
        );
        config.setSupportedSignatureAndHashAlgorithms(config.getDefaultServerSupportedSignatureAndHashAlgorithms());

        config.setDefaultServerSupportedCiphersuites(CipherSuite.getImplemented().stream().filter(CipherSuite::isTLS13).collect(Collectors.toList()));
        config.setDefaultClientSupportedCiphersuites(config.getDefaultServerSupportedCiphersuites());
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultClientNamedGroups(Arrays.stream(NamedGroup.values()).filter(NamedGroup::isTls13).collect(Collectors.toList()));
        config.setDefaultServerNamedGroups(config.getDefaultClientNamedGroups());
        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
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

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public String getOutputFormat() {
        return outputFormat;
    }

    public void setOutputFormat(String outputFormat) {
        this.outputFormat = outputFormat;
    }

    public boolean isParsedArgs() {
        return parsedArgs;
    }

    public int getParallel() {
        return parallel;
    }

    public void setParallel(int parallel) {
        this.parallel = parallel;
    }

    public List<ProtocolVersion> getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(List<ProtocolVersion> supportedVersions) {
        this.supportedVersions = supportedVersions;
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
}
