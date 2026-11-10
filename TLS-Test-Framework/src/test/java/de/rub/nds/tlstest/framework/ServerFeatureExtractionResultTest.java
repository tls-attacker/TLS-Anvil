package de.rub.nds.tlstest.framework;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.LongResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlstest.framework.exceptions.FeatureExtractionFailedException;
import java.util.List;
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

    /**
     * A TLS 1.3-only server: the scanner never sets the TLS 1.2-only properties (compression
     * methods, ServerKeyExchange algorithms, TLS 1.2 group witnesses). Extraction used to fail with
     * a NullPointerException on them.
     */
    @Test
    public void testTls13OnlyServerScanReport() {
        ServerReport report = new ServerReport("hostname", 4433);
        List<CipherSuite> suites = List.of(CipherSuite.TLS_AES_128_GCM_SHA256);
        List<NamedGroup> groups = List.of(NamedGroup.ECDH_X25519);
        put(report, TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, suites);
        put(
                report,
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                List.of(ProtocolVersion.TLS13));
        put(
                report,
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                List.of(new VersionSuiteListPair(ProtocolVersion.TLS13, suites)));
        put(report, TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS, List.of());
        put(report, TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS, groups);
        report.putResult(
                TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA,
                new LongResult(TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA, 0L));
        report.putResult(
                TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA,
                new LongResult(TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA, 0L));

        ServerFeatureExtractionResult result =
                ServerFeatureExtractionResult.fromServerScanReport(report);

        assertEquals(groups, result.getTls13Groups());
        assertTrue(result.getSupportedCompressionMethods().isEmpty());
        assertTrue(result.getSupportedSignatureAndHashAlgorithmsSke().isEmpty());
        assertTrue(result.getNamedGroupWitnesses().isEmpty());
        assertTrue(result.getNegotiableExtensions().isEmpty());
    }

    private static <T> void put(ServerReport report, TlsAnalyzedProperty property, List<T> list) {
        report.putResult(property, new ListResult<>(property, list));
    }
}
