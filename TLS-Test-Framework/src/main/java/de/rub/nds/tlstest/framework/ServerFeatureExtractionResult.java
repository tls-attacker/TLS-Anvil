package de.rub.nds.tlstest.framework;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.probe.result.NotApplicableResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportPrinter;
import java.util.*;

public class ServerFeatureExtractionResult extends FeatureExtractionResult {

    private Set<ExtensionType> negotiableExtensions = new HashSet<>();
    private Map<NamedGroup, NamedGroupWitness> namedGroupWitnesses = new HashMap<>();
    private Map<NamedGroup, NamedGroupWitness> namedGroupWitnessesTls13 = new HashMap<>();
    private Set<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithmsSke = new HashSet<>();
    private String configProfileIdentifier = "";
    private String configProfileIdentifierTls13 = "";

    @JsonIgnore private List<JsonNode> guidelineChecks = new ArrayList<>();

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
        // The scanner leaves a property unset when its probe does not apply: a TLS 1.3-only
        // server has no TLS 1.2 compression methods, ServerKeyExchange algorithms or
        // TLS 1.2 group witnesses. Unset means none.
        addAllIfPresent(
                extractionResult.getSupportedCompressionMethods(),
                serverReport.getSupportedCompressionMethods());
        if (serverReport.getSupportedNamedGroupsWitnesses() != null) {
            extractionResult.setNamedGroupWitnesses(
                    serverReport.getSupportedNamedGroupsWitnesses());
        }
        if (serverReport.getSupportedNamedGroupsWitnessesTls13() != null) {
            extractionResult.setNamedGroupWitnessesTls13(
                    serverReport.getSupportedNamedGroupsWitnessesTls13());
        }
        addAllIfPresent(
                extractionResult.getSupportedSignatureAndHashAlgorithmsSke(),
                serverReport.getSupportedSignatureAndHashAlgorithmsSke());
        extractionResult.setConfigProfileIdentifier(serverReport.getConfigProfileIdentifier());
        extractionResult.setConfigProfileIdentifierTls13(
                serverReport.getConfigProfileIdentifierTls13());
        addAllIfPresent(
                extractionResult.getNegotiableExtensions(), serverReport.getSupportedExtensions());

        extractionResult.setGuidelineChecks(getGuidelines(serverReport.getGuidelineReports()));
        extractionResult.setTestReport(
                new ServerReportPrinter(
                                serverReport,
                                ScannerDetail.NORMAL,
                                DefaultPrintingScheme.getDefaultPrintingScheme(),
                                true)
                        .getFullReport());

        return extractionResult;
    }

    private static <T> void addAllIfPresent(Collection<T> target, Collection<T> source) {
        if (source != null) {
            target.addAll(source);
        }
    }

    private static List<JsonNode> getGuidelines(List<GuidelineReport> reports) {
        List<JsonNode> guidelineList = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();
        for (GuidelineReport report : reports) {
            // add an info node with extra information that the mapper would not pick up by itself
            JsonNode jsonGuideline = mapper.valueToTree(report);
            for (int i = 0; i < report.getResults().size(); i++) {
                ObjectNode node = (ObjectNode) jsonGuideline.get("results").get(i);
                node.put("info", report.getResults().get(i).toString());
            }
            guidelineList.add(jsonGuideline);
        }

        return guidelineList;
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

    public List<JsonNode> getGuidelineChecks() {
        return guidelineChecks;
    }

    public void setGuidelineChecks(List<JsonNode> guidelineChecks) {
        this.guidelineChecks = guidelineChecks;
    }
}
