/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.CollectionResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.closing.ConnectionClosingUtils;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlstest.framework.exceptions.FeatureExtractionFailedException;
import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

public abstract class FeatureExtractionResult implements Serializable {

    private final String host;
    private final int port;

    private Set<CipherSuite> supportedCipherSuites = new HashSet<>();
    private Set<ProtocolVersion> supportedVersions = new HashSet<>();
    private Set<NamedGroup> supportedNamedGroups = new HashSet<>();
    private List<VersionSuiteListPair> versionSuitePairs = new LinkedList<>();
    private Set<CompressionMethod> supportedCompressionMethods = new HashSet<>();
    private Set<NamedGroup> supportedTls13Groups = new HashSet<>();

    private Map<AnalyzedProperty, TestResult> resultMap;

    private long closedAfterAppDataDelta = ConnectionClosingUtils.NO_RESULT;
    private long closedAfterFinishedDelta = ConnectionClosingUtils.NO_RESULT;

    public FeatureExtractionResult(String host) {
        this.host = host;
        this.port = 4433;
    }

    public FeatureExtractionResult(String host, int port) {
        this.host = host;
        this.port = port;
    }

    protected void setSharedFieldsFromReport(TlsScanReport siteReport) {
        checkCrucialCollections(
                siteReport,
                TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS,
                TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS);
        setResultMap(siteReport.getResultMap());
        for (VersionSuiteListPair versionSuiteListPair : siteReport.getVersionSuitePairs()) {
            if (versionSuiteListPair.getVersion() == ProtocolVersion.TLS12
                    || versionSuiteListPair.getVersion() == ProtocolVersion.TLS13
                    || versionSuiteListPair.getVersion() == ProtocolVersion.DTLS12) {
                getSupportedCipherSuites().addAll(versionSuiteListPair.getCipherSuiteList());
            }
        }
        getSupportedVersions().addAll(siteReport.getSupportedProtocolVersions());
        getVersionSuitePairs().addAll(siteReport.getVersionSuitePairs());
        getSupportedNamedGroups().addAll(siteReport.getSupportedNamedGroups());
        getSupportedTls13Groups().addAll(siteReport.getSupportedTls13Groups());

        setClosedAfterAppDataDelta(siteReport.getClosedAfterAppDataDelta());
        setClosedAfterFinishedDelta(siteReport.getClosedAfterFinishedDelta());
    }

    public List<NamedGroup> getNamedGroups() {
        // We limit the tests to EC Named Groups for now
        return getSupportedNamedGroups().stream()
                .filter(NamedGroup::isCurve)
                .collect(Collectors.toList());
    }

    public List<NamedGroup> getTls13Groups() {
        // We limit the tests to EC Named Groups for now
        return getSupportedTls13Groups().stream()
                .filter(NamedGroup::isCurve)
                .collect(Collectors.toList());
    }

    public List<NamedGroup> getFfdheNamedGroups() {
        // We only use these for FFDHE RFC tests for now
        return getSupportedNamedGroups().stream()
                .filter(NamedGroup::isDhGroup)
                .collect(Collectors.toList());
    }

    public List<NamedGroup> getTls13FfdheNamedGroups() {
        // We limit the tests to EC Named Groups for now
        return getTls13Groups().stream().filter(NamedGroup::isDhGroup).collect(Collectors.toList());
    }

    public synchronized Set<CipherSuite> getCipherSuites() {
        if (getSupportedCipherSuites() == null) return new TreeSet<>();
        Set<CipherSuite> set =
                new TreeSet<CipherSuite>(
                        (a, b) -> String.CASE_INSENSITIVE_ORDER.compare(a.name(), b.name()));
        set.addAll(
                getSupportedCipherSuites().stream()
                        .filter(i -> !i.isTLS13())
                        .collect(Collectors.toSet()));
        return set;
    }

    public synchronized Set<CipherSuite> getSupportedTls13CipherSuites() {
        if (getSupportedCipherSuites() == null) return new TreeSet<>();
        Set<CipherSuite> set =
                new TreeSet<CipherSuite>(
                        (a, b) -> String.CASE_INSENSITIVE_ORDER.compare(a.name(), b.name()));
        set.addAll(
                getSupportedCipherSuites().stream()
                        .filter(CipherSuite::isTLS13)
                        .collect(Collectors.toSet()));
        return set;
    }

    public Set<CipherSuite> getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    public void setSupportedCipherSuites(Set<CipherSuite> supportedCipherSuites) {
        this.supportedCipherSuites = supportedCipherSuites;
    }

    public Set<ProtocolVersion> getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(Set<ProtocolVersion> supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public void setSupportedNamedGroups(Set<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public Set<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(Set<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public void setSupportedTls13Groups(Set<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public Map<AnalyzedProperty, TestResult> getResultMap() {
        return resultMap;
    }

    public void setResultMap(Map<AnalyzedProperty, TestResult> resultMap) {
        this.resultMap = resultMap;
    }

    public long getClosedAfterAppDataDelta() {
        return closedAfterAppDataDelta;
    }

    public void setClosedAfterAppDataDelta(long closedAfterAppDataDelta) {
        this.closedAfterAppDataDelta = closedAfterAppDataDelta;
    }

    public long getClosedAfterFinishedDelta() {
        return closedAfterFinishedDelta;
    }

    public void setClosedAfterFinishedDelta(long closedAfterFinishedDelta) {
        this.closedAfterFinishedDelta = closedAfterFinishedDelta;
    }

    public TestResult getResult(TlsAnalyzedProperty property) {
        return resultMap.get(property);
    }

    public abstract Set<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithmsForDerivation();

    public Set<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public Set<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    protected static void checkCrucialCollections(
            TlsScanReport report, TlsAnalyzedProperty... properties) {
        List<TlsAnalyzedProperty> malformedProperties = new LinkedList<>();
        for (TlsAnalyzedProperty property : properties) {
            if (report.getResult(property) == null
                    || !(report.getResult(property) instanceof CollectionResult)) {
                malformedProperties.add(property);
            }
        }

        if (!malformedProperties.isEmpty()) {
            throw new FeatureExtractionFailedException(
                    "Preparation was unable to determine the following features: "
                            + malformedProperties.stream()
                                    .map(TlsAnalyzedProperty::getName)
                                    .collect(Collectors.joining(", ")));
        }
    }

    protected static void reportFailedFeatureExtraction(String reason) {
        throw new FeatureExtractionFailedException(reason);
    }
}
