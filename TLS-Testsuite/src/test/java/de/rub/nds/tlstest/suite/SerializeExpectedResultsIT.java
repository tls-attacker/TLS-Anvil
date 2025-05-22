package de.rub.nds.tlstest.suite;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.anvilcore.teststate.reporting.MetadataFetcher;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.File;
import java.io.IOException;
import java.util.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class SerializeExpectedResultsIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serializeTlsTestConfigServer() {

        AnvilTestConfig testConfig = new AnvilTestConfig();
        MetadataFetcher metadataFetcher = new MetadataFetcher();
        Iterator<String> allTestIds = metadataFetcher.getAllTestIds().iterator();
        Map<TestResult, Set<String>> resultSetMap = new HashMap<>();
        for (TestResult testResult : TestResult.values()) {
            resultSetMap.put(testResult, Set.of(allTestIds.next(), allTestIds.next()));
        }
        testConfig.setExpectedResultsMap(resultSetMap);
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(
                            new File("../config_examples/expected_results.json"),
                            testConfig.getExpectedResultsMap());

        } catch (IOException e) {
            Assertions.fail("Error during serialization of expected results.", e);
        }
    }
}
