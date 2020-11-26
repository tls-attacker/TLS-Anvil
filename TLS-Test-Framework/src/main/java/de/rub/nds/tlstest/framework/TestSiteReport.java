/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

public class TestSiteReport extends SiteReport {

    @JsonIgnore
    private ClientHelloMessage receivedClientHello;

    public TestSiteReport(String host) {
        super(host);
    }

    private TestSiteReport() {
        super();
    }

    public static TestSiteReport fromSiteReport(SiteReport siteReport) {
        try {
            TestSiteReport report = new TestSiteReport();

            report.setCipherSuites(siteReport.getCipherSuites());
            report.setSupportedSignatureAndHashAlgorithms(siteReport.getSupportedSignatureAndHashAlgorithms());
            report.setVersions(siteReport.getVersions());
            report.setSupportedNamedGroups(siteReport.getSupportedNamedGroups());
            report.setVersionSuitePairs(siteReport.getVersionSuitePairs());
            report.setSupportedCompressionMethods(siteReport.getSupportedCompressionMethods());
            report.setSupportedTls13Groups(siteReport.getSupportedTls13Groups());
            report.setSupportedNamedGroupsWitnesses(siteReport.getSupportedNamedGroupsWitnesses());
            report.setSupportedNamedGroupsWitnessesTls13(siteReport.getSupportedNamedGroupsWitnessesTls13());
            report.setSupportedExtensions(siteReport.getSupportedExtensions());
            report.setSupportsRecordFragmentation(siteReport.getSupportsRecordFragmentation());
            
            for(String key : siteReport.getResultMap().keySet()) {
                report.putResult(AnalyzedProperty.valueOf(key), siteReport.getResultMap().get(key));
            }
            
            return report;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public ClientHelloMessage getReceivedClientHello() {
        return receivedClientHello;
    }

    public void setReceivedClientHello(ClientHelloMessage receivedClientHelloMessage) {
        this.receivedClientHello = receivedClientHelloMessage;
    }

    @Override
    public synchronized Set<CipherSuite> getCipherSuites() {
        if (super.getCipherSuites() == null) return new TreeSet<>();
        Set<CipherSuite> set = new TreeSet<CipherSuite>((a, b) -> String.CASE_INSENSITIVE_ORDER.compare(a.name(), b.name()));
        set.addAll(super.getCipherSuites().stream().filter(i -> !i.isTLS13()).collect(Collectors.toSet()));
        return set;
    }

    public synchronized Set<CipherSuite> getSupportedTls13CipherSuites() {
        if (super.getCipherSuites() == null) return new TreeSet<>();
        Set<CipherSuite> set = new TreeSet<CipherSuite>((a, b) -> String.CASE_INSENSITIVE_ORDER.compare(a.name(), b.name()));
        set.addAll(super.getCipherSuites().stream().filter(CipherSuite::isTLS13).collect(Collectors.toSet()));
        return set;
    }
}
