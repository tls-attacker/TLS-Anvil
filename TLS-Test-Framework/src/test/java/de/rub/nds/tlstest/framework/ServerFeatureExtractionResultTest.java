package de.rub.nds.tlstest.framework;

import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlstest.framework.exceptions.FeatureExtractionFailedException;
import org.junit.jupiter.api.Test;

public class ServerFeatureExtractionResultTest {

    public ServerFeatureExtractionResultTest() {}

    @Test
    public void testFromEmptyServerScanReport() {
        ServerReport emptyReport = new ServerReport("hostname", 4433);
        assertThrows(
                FeatureExtractionFailedException.class,
                () -> ServerFeatureExtractionResult.fromServerScanReport(emptyReport));
    }
}
