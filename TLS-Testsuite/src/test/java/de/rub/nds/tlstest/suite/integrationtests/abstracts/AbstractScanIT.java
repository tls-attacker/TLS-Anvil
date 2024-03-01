package de.rub.nds.tlstest.suite.integrationtests.abstracts;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.command.ListContainersCmd;
import com.github.dockerjava.api.model.Image;
import com.google.common.collect.Sets;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.execution.TestRunner;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerClientManager;
import de.rub.nds.tls.subject.docker.DockerTlsInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import de.rub.nds.tlstest.framework.config.TlsTestConfig;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.Security;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

public abstract class AbstractScanIT {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected AnvilTestConfig anvilTestConfig = new AnvilTestConfig();
    protected TlsTestConfig tlsConfig = new TlsTestConfig();
    protected TestContext testContext = TestContext.getInstance();
    protected DockerTlsInstance dockerInstance;

    private final TlsImplementationType implementation;
    private final String version;
    private final ConnectionRole dockerConnectionRole;

    private static final boolean EXPORT_RESULT_TEST_MAP = false;

    public AbstractScanIT(
            TlsImplementationType implementation, ConnectionRole connectionRole, String version) {
        this.implementation = implementation;
        this.dockerConnectionRole = connectionRole;
        this.version = version;
    }

    @Test
    public void startTest() {
        setUpDockerClientManager();
        List<Image> images = loadDockerImages();
        Image image = setupDockerImage(images);
        dockerInstance = startDockerContainer(image, implementation, version, TransportType.TCP);
        setUpTest();
        setUpTestRunner().runTests();
        checkResults();
        if (EXPORT_RESULT_TEST_MAP) {
            serializeResults();
        }
    }

    @After
    public void afterTest() {
        dockerInstance.stop();
        dockerInstance.remove();
    }

    private final void setUpDockerClientManager() {
        Security.addProvider(new BouncyCastleProvider());
        DockerClientManager.setDockerServerUsername(System.getenv("DOCKER_USERNAME"));
        DockerClientManager.setDockerServerPassword(System.getenv("DOCKER_PASSWORD"));
    }

    private static List<Image> loadDockerImages() {
        try (ListContainersCmd cmd = DockerClientManager.getDockerClient().listContainersCmd()) {
            cmd.exec();
        } catch (Exception e) {
            LOGGER.error(String.format("Error while loading list of Docker containers: %s", e));
            Assume.assumeNoException(e);
        }
        return DockerTlsManagerFactory.getAllImages();
    }

    private Image setupDockerImage(List<Image> images) {
        return DockerTlsManagerFactory.getMatchingImage(
                images, implementation, version, dockerConnectionRole);
    }

    protected abstract DockerTlsInstance startDockerContainer(
            Image image,
            TlsImplementationType implementation,
            String version,
            TransportType transportType);

    protected void setUpTest() {
        // AnvilTestConfig
        anvilTestConfig.setDisableTcpDump(true);
        anvilTestConfig.setIgnoreCache(true);
        anvilTestConfig.setOutputFolder("/tmp/TLS-Anvil-Out-" + new Random().nextInt());
        anvilTestConfig.setTestPackage("de.rub.nds.tlstest.suite");
        setUpAnvilTestConfig(anvilTestConfig);
        // TlsTestConfig
        tlsConfig.setAnvilTestConfig(anvilTestConfig);
        tlsConfig
                .getGeneralDelegate()
                .setKeylogfile(
                        Path.of(anvilTestConfig.getOutputFolder(), "keyfile.log").toString());
        tlsConfig.setParsedArgs(true);
        setUpTlsTestConfig(tlsConfig);
    }

    protected abstract void setUpAnvilTestConfig(AnvilTestConfig anvilTestConfig);

    protected abstract void setUpTlsTestConfig(TlsTestConfig tlsConfig);

    private TestRunner setUpTestRunner() {
        testContext.setConfig(tlsConfig);
        ObjectMapper mapper = new ObjectMapper();
        String additionalConfig = "";
        try {
            additionalConfig = mapper.writeValueAsString(testContext.getConfig());
        } catch (JsonProcessingException e) {
            LOGGER.error(String.format("Error while parsing TlsTestConfig: %s", e));
            Assume.assumeNoException(e);
        }
        TestRunner testRunner =
                new TestRunner(
                        anvilTestConfig, additionalConfig, new TlsParameterIdentifierProvider());
        testRunner.setListener(testContext);
        return testRunner;
    }

    protected void checkResults() {
        String expectedResultsFileName =
                String.format(
                        "expected_results_%s-%s%s.json",
                        implementation.name().toLowerCase(),
                        dockerConnectionRole.name().toLowerCase(),
                        version);
        ObjectMapper mapper = new ObjectMapper();
        Map<TestResult, Set<String>> expectedResults = null;
        TypeReference<HashMap<TestResult, Set<String>>> typeRef = new TypeReference<>() {};
        try (InputStream inputFile =
                getClass().getClassLoader().getResourceAsStream(expectedResultsFileName)) {
            expectedResults = mapper.readValue(inputFile, typeRef);
        } catch (IOException e) {
            LOGGER.error(
                    String.format("Error while parsing file %s: %s", expectedResultsFileName, e));
            Assume.assumeNoException(e);
        }

        Map<TestResult, Set<String>> results = AnvilContext.getInstance().getResultTestMap();
        Map<String, TestResult> orderedActualResults = new HashMap<>();
        Map<String, TestResult> orderedExpectedResults = new HashMap<>();
        for (Map.Entry<TestResult, Set<String>> entry : results.entrySet()) {
            for (String s : entry.getValue()) {
                orderedActualResults.put(s, entry.getKey());
            }
        }
        for (Map.Entry<TestResult, Set<String>> entry : expectedResults.entrySet()) {
            for (String s : entry.getValue()) {
                orderedExpectedResults.put(s, entry.getKey());
            }
        }

        boolean fail = false;
        StringBuilder builder = new StringBuilder();
        builder.append(String.format(" %-20s| %-20s| %-20s\n", "Actual", "Expected", "Test"));
        builder.append("---------------------+---------------------+---------------------\n");
        for (String s :
                Sets.union(orderedActualResults.keySet(), orderedExpectedResults.keySet())) {
            String shortName = s.substring(31);
            if (!orderedActualResults.containsKey(s)) {
                builder.append(
                        String.format(
                                " %-20s| %-20s| %-20s\n",
                                "missing", orderedExpectedResults.get(s), shortName));
                fail = true;
            } else if (!orderedExpectedResults.containsKey(s)) {
                builder.append(
                        String.format(
                                " %-20s| %-20s| %-20s\n",
                                orderedActualResults.get(s), "not present", shortName));
                fail = true;
            } else if (orderedActualResults.get(s) != orderedExpectedResults.get(s)) {
                builder.append(
                        String.format(
                                " %-20s| %-20s| %-20s\n",
                                orderedActualResults.get(s),
                                orderedExpectedResults.get(s),
                                shortName));
                fail = true;
            }
        }
        if (fail) {
            System.err.print(builder);
            Assert.fail("Test results do not match with expected results.");
        }
    }

    protected void serializeResults() {
        ObjectMapper mapper = new ObjectMapper();
        String serializeResultsFileName =
                "result_test_map_" + anvilTestConfig.getIdentifier() + version + ".json";
        File f = new File(anvilTestConfig.getOutputFolder(), serializeResultsFileName);
        Map<TestResult, Set<String>> results = AnvilContext.getInstance().getResultTestMap();
        try {
            mapper.writeValue(f, results);
        } catch (IOException e) {
            Assume.assumeNoException(e);
        }
    }
}
