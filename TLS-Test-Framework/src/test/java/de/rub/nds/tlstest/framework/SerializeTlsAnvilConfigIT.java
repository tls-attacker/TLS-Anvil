package de.rub.nds.tlstest.framework;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlstest.framework.config.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class SerializeTlsAnvilConfigIT {

    private static AnvilTestConfig anvilTestConfig;

    @BeforeAll
    public static void generateAnvilTestConfig() {
        anvilTestConfig = new AnvilTestConfig();
        anvilTestConfig.setExpectedResults("expected_results.json");
        anvilTestConfig.setProfileFolder("./profiles");
        anvilTestConfig.setGeneralPcapFilter(null);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serializeTlsTestConfigServer() {
        TlsAnvilConfig anvilConfig = new TlsAnvilConfig();
        anvilTestConfig.setIdentifier("example_server_test");
        anvilTestConfig.setParallelTests((int) (anvilConfig.getParallelHandshakes() * 1.5));
        anvilConfig.setAnvilTestConfig(anvilTestConfig);
        TestServerDelegate testServerDelegate = new TestServerDelegate();
        testServerDelegate.setHost("localhost:8443");
        anvilConfig.setTestServerDelegate(testServerDelegate);
        anvilConfig.setTestClientDelegate(null);
        anvilConfig.setTestEndpointMode(TestEndpointType.SERVER);

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(new File("../config_examples/server_config.json"), anvilConfig);

        } catch (IOException e) {
            Assertions.fail("Error during serialization of server config file.", e);
        }
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serializeTlsTestConfigClient() {
        TlsAnvilConfig tlsAnvilConfig = new TlsAnvilConfig();
        AnvilTestConfig anvilTestConfig = new AnvilTestConfig();
        anvilTestConfig.setIdentifier("example_client_test");
        anvilTestConfig.setParallelTests((int) (tlsAnvilConfig.getParallelHandshakes() * 1.5));
        tlsAnvilConfig.setAnvilTestConfig(anvilTestConfig);
        TestClientDelegate clientConfig = new TestClientDelegate();
        clientConfig.setTriggerScriptCommand(List.of("curl", "localhost:8090/trigger"));
        tlsAnvilConfig.setTestClientDelegate(clientConfig);
        tlsAnvilConfig.setTestServerDelegate(null);
        tlsAnvilConfig.setTestEndpointMode(TestEndpointType.CLIENT);

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(new File("../config_examples/client_config.json"), tlsAnvilConfig);

        } catch (IOException e) {
            Assertions.fail("Error during serialization of client config file.", e);
        }
    }
}
