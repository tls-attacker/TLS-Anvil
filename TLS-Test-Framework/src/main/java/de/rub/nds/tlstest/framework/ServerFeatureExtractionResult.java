package de.rub.nds.tlstest.framework;

import de.rub.nds.scanner.core.constants.NotApplicableResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ServerFeatureExtractionResult extends FeatureExtractionResult {

    private Set<ExtensionType> negotiableExtensions = new HashSet<>();
    private Map<NamedGroup, NamedGroupWitness> namedGroupWitnesses = new HashMap<>();
    private Map<NamedGroup, NamedGroupWitness> namedGroupWitnessesTls13 = new HashMap<>();
    private Set<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsSke = new HashSet<>();
    private String configProfileIdentifier = "";
    private String configProfileIdentifierTls13 = "";

    public ServerFeatureExtractionResult(String host, int port) {
        super(host, 4433);
    }

    public static ServerFeatureExtractionResult fromServerScanReport(ServerReport serverReport) {
        ServerFeatureExtractionResult extractionResult =
                new ServerFeatureExtractionResult(serverReport.getHost(), serverReport.getPort());
        serverReport.putResult(
                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                new NotApplicableResult(TlsAnalyzedProperty.CERTIFICATE_CHAINS, ""));
        serverReport.putResult(
                TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES,
                new NotApplicableResult(TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES, ""));
        extractionResult.setSharedFieldsFromReport(serverReport);

        // move to shared fields when scanner is updated
        extractionResult
                .getSupportedCompressionMethods()
                .addAll(serverReport.getSupportedCompressionMethods());

        extractionResult.setNamedGroupWitnesses(serverReport.getSupportedNamedGroupsWitnesses());
        extractionResult.setNamedGroupWitnessesTls13(
                serverReport.getSupportedNamedGroupsWitnessesTls13());
        extractionResult
                .getSupportedSignatureAndHashAlgorithmsSke()
                .addAll(serverReport.getSupportedSignatureAndHashAlgorithmsSke());
        extractionResult.setConfigProfileIdentifier(serverReport.getConfigProfileIdentifier());
        extractionResult.setConfigProfileIdentifierTls13(
                serverReport.getConfigProfileIdentifierTls13());
        extractionResult.getNegotiableExtensions().addAll(serverReport.getSupportedExtensions());

        return extractionResult;
    }

    public String getConfigProfileIdentifier() {
        return configProfileIdentifier;
    }

    public void setConfigProfileIdentifier(String configProfileIdentifier) {
        this.configProfileIdentifier = configProfileIdentifier;
    }

    public String getConfigProfileIdentifierTls13() {
        return configProfileIdentifierTls13;
    }

    public void setConfigProfileIdentifierTls13(String configProfileIdentifierTls13) {
        this.configProfileIdentifierTls13 = configProfileIdentifierTls13;
    }

    public Map<NamedGroup, NamedGroupWitness> getNamedGroupWitnesses() {
        return namedGroupWitnesses;
    }

    public void setNamedGroupWitnesses(Map<NamedGroup, NamedGroupWitness> namedGroupWitnesses) {
        this.namedGroupWitnesses = namedGroupWitnesses;
    }

    public Map<NamedGroup, NamedGroupWitness> getNamedGroupWitnessesTls13() {
        return namedGroupWitnessesTls13;
    }

    public void setNamedGroupWitnessesTls13(
            Map<NamedGroup, NamedGroupWitness> namedGroupWitnessesTls13) {
        this.namedGroupWitnessesTls13 = namedGroupWitnessesTls13;
    }

    public Set<ExtensionType> getNegotiableExtensions() {
        return negotiableExtensions;
    }

    public void setNegotiableExtensions(Set<ExtensionType> negotiableExtensions) {
        this.negotiableExtensions = negotiableExtensions;
    }

    @Override
    public Set<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithmsForDerivation() {
        return getSupportedSignatureAndHashAlgorithmsSke();
    }

    public Set<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
        return supportedSignatureAndHashAlgorithmsSke;
    }

    public void setSupportedSignatureAndHashAlgorithmsSke(
            Set<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsSke) {
        this.supportedSignatureAndHashAlgorithmsSke = supportedSignatureAndHashAlgorithmsSke;
    }
}
