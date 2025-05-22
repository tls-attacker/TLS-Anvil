package de.rub.nds.tlstest.suite;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.context.Profile;
import de.rub.nds.anvilcore.teststate.reporting.MetadataFetcher;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class SerializeProfileIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serializeProfile() {
        MetadataFetcher metadataFetcher = new MetadataFetcher();
        Iterator<String> testIds = metadataFetcher.getAllTestIds().iterator();
        Profile profile = new Profile();
        profile.setName("example_profile");
        profile.setTestIds(List.of(testIds.next(), testIds.next()));

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(new File("../config_examples/example_profile.json"), profile);

        } catch (IOException e) {
            Assertions.fail("Error during serialization of profile.", e);
        }
    }
}
