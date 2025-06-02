package de.rub.nds.tlstest.framework;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlstest.framework.config.TlsTestConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class SerializeTlsTestConfigIT {

    private static AnvilTestConfig anvilTestConfig;

    @BeforeAll
    public static void generateAnvilTestConfig() {
        anvilTestConfig = new AnvilTestConfig();
        anvilTestConfig.setExpectedResults("expected_results.json");
        anvilTestConfig.setParallelTests((int) (anvilTestConfig.getParallelTestCases() * 1.5));
        anvilTestConfig.setProfileFolder("./profiles");
        anvilTestConfig.setGeneralPcapFilter(null);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serializeTlsTestConfigServer() {
        TlsTestConfig testConfig = new TlsTestConfig();
        anvilTestConfig.setIdentifier("example_server_test");
        testConfig.setAnvilTestConfig(anvilTestConfig);
        TestServerDelegate testServerDelegate = new TestServerDelegate();
        testServerDelegate.setHost("localhost:8443");
        testConfig.setTestServerDelegate(testServerDelegate);
        testConfig.setTestClientDelegate(null);
        testConfig.setTestEndpointMode(TestEndpointType.SERVER);

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(new File("../config_examples/server_config.json"), testConfig);

        } catch (IOException e) {
            Assertions.fail("Error during serialization of server config file.", e);
        }
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serializeTlsTestConfigClient() {
        TlsTestConfig testConfig = new TlsTestConfig();
        AnvilTestConfig anvilTestConfig = new AnvilTestConfig();
        anvilTestConfig.setIdentifier("example_client_test");
        testConfig.setAnvilTestConfig(anvilTestConfig);
        TestClientDelegate clientConfig = new TestClientDelegate();
        clientConfig.setTriggerScriptCommand(List.of("curl", "localhost:8090/trigger"));
        testConfig.setTestClientDelegate(clientConfig);
        testConfig.setTestServerDelegate(null);
        testConfig.setTestEndpointMode(TestEndpointType.CLIENT);

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(new File("../config_examples/client_config.json"), testConfig);

        } catch (IOException e) {
            Assertions.fail("Error during serialization of client config file.", e);
        }
    }
}
