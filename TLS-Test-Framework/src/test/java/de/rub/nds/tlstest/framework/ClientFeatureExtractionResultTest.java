package de.rub.nds.tlstest.framework;

import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlstest.framework.exceptions.FeatureExtractionFailedException;
import org.junit.jupiter.api.Test;

public class ClientFeatureExtractionResultTest {

    public ClientFeatureExtractionResultTest() {}

    @Test
    public void testFromEmptyClientScanReport() {
        ClientReport emptyReport = new ClientReport();
        assertThrows(
                FeatureExtractionFailedException.class,
                () -> ClientFeatureExtractionResult.fromClientScanReport(emptyReport, "test"));
    }
}
