package de.rub.nds.tlstest.framework;

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ClientFeatureExtractionResult extends FeatureExtractionResult {

    @JsonIgnore private ClientHelloMessage receivedClientHello;

    private int requiredCertificateDSSPublicKeySize;
    private int requiredCertificateRSAPublicKeySize;
    private List<SignatureAndHashAlgorithm> advertisedSignatureAndHashAlgorithms =
            new LinkedList<>();
    private List<ExtensionType> advertisedExtensions = new LinkedList<>();

    public ClientFeatureExtractionResult(String host) {
        super(host);
    }

    public static ClientFeatureExtractionResult fromClientScanReport(ClientReport report) {
        ClientFeatureExtractionResult extractionResult =
                new ClientFeatureExtractionResult("client");
        extractionResult.setSharedFieldsFromReport(report);

        extractionResult
                .getSupportedNamedGroups()
                .addAll(report.getClientAdvertisedNamedGroupsList());
        extractionResult
                .getSupportedTls13Groups()
                .addAll(report.getClientAdvertisedKeyShareNamedGroupsList());
        extractionResult
                .getSupportedCompressionMethods()
                .addAll(report.getClientAdvertisedCompressions());

        extractionResult.setRequiredCertificateDSSPublicKeySize(
                report.getMinimumServerCertificateKeySizeDSS());
        extractionResult.setRequiredCertificateRSAPublicKeySize(
                report.getMinimumServerCertificateKeySizeRSA());
        extractionResult
                .getAdvertisedSignatureAndHashAlgorithms()
                .addAll(report.getClientAdvertisedSignatureAndHashAlgorithms());
        extractionResult.getAdvertisedExtensions().addAll(report.getClientAdvertisedExtensions());
        return extractionResult;
    }

    public int getRequiredCertificateDSSPublicKeySize() {
        return requiredCertificateDSSPublicKeySize;
    }

    public void setRequiredCertificateDSSPublicKeySize(int requiredCertificateDSSPublicKeySize) {
        this.requiredCertificateDSSPublicKeySize = requiredCertificateDSSPublicKeySize;
    }

    public int getRequiredCertificateRSAPublicKeySize() {
        return requiredCertificateRSAPublicKeySize;
    }

    public void setRequiredCertificateRSAPublicKeySize(int requiredCertificateRSAPublicKeySize) {
        this.requiredCertificateRSAPublicKeySize = requiredCertificateRSAPublicKeySize;
    }

    public List<SignatureAndHashAlgorithm> getAdvertisedSignatureAndHashAlgorithms() {
        return advertisedSignatureAndHashAlgorithms;
    }

    public void setAdvertisedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> advertisedSignatureAndHashAlgorithms) {
        this.advertisedSignatureAndHashAlgorithms = advertisedSignatureAndHashAlgorithms;
    }

    @Override
    public Set<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithmsForDerivation() {
        return new HashSet<>(getAdvertisedSignatureAndHashAlgorithms());
    }

    public List<ExtensionType> getAdvertisedExtensions() {
        return advertisedExtensions;
    }

    public void setAdvertisedExtensions(List<ExtensionType> advertisedExtensions) {
        this.advertisedExtensions = advertisedExtensions;
    }

    public ClientHelloMessage getReceivedClientHello() {
        return receivedClientHello;
    }

    public List<NamedGroup> getClientHelloKeyShareGroups() {
        List<NamedGroup> keyShareGroups = new LinkedList<>();
        if (receivedClientHello != null
                && receivedClientHello.containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage keyshare =
                    receivedClientHello.getExtension(KeyShareExtensionMessage.class);
            for (KeyShareEntry ksEntry : keyshare.getKeyShareList()) {
                keyShareGroups.add(ksEntry.getGroupConfig());
            }
        }
        return keyShareGroups;
    }

    public List<NamedGroup> getClientHelloNamedGroups() {
        if (receivedClientHello != null
                && receivedClientHello.containsExtension(ExtensionType.ELLIPTIC_CURVES)) {
            return NamedGroup.namedGroupsFromByteArray(
                    receivedClientHello
                            .getExtension(EllipticCurvesExtensionMessage.class)
                            .getSupportedGroups()
                            .getValue());
        }
        return new LinkedList<>();
    }

    public void setReceivedClientHello(ClientHelloMessage receivedClientHelloMessage) {
        this.receivedClientHello = receivedClientHelloMessage;
    }
}
