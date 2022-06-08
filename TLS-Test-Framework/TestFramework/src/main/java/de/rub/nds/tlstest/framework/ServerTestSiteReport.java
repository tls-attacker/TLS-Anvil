/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

public class ServerTestSiteReport extends ServerReport {

    @JsonIgnore
    private ClientHelloMessage receivedClientHello;

    public ServerTestSiteReport(String host) {
        super(host, 4433);
    }
    
    public ServerTestSiteReport(String host, int port) {
        super(host, port);
    }

    public static ServerTestSiteReport fromSiteReport(ServerReport siteReport) {
        try {
            ServerTestSiteReport report = new ServerTestSiteReport(siteReport.getHost(), siteReport.getPort());

            report.setCipherSuites(siteReport.getCipherSuites());
            report.setSupportedSignatureAndHashAlgorithmsSke(siteReport.getSupportedSignatureAndHashAlgorithms());
            report.setVersions(siteReport.getVersions());
            report.setSupportedNamedGroups(siteReport.getSupportedNamedGroups());
            report.setVersionSuitePairs(siteReport.getVersionSuitePairs());
            report.setSupportedCompressionMethods(siteReport.getSupportedCompressionMethods());
            report.setSupportedTls13Groups(siteReport.getSupportedTls13Groups());
            report.setSupportedNamedGroupsWitnesses(siteReport.getSupportedNamedGroupsWitnesses());
            report.setSupportedNamedGroupsWitnessesTls13(siteReport.getSupportedNamedGroupsWitnessesTls13());
            report.setSupportedExtensions(siteReport.getSupportedExtensions());
            report.setClosedAfterAppDataDelta(siteReport.getClosedAfterAppDataDelta());
            report.setClosedAfterFinishedDelta(siteReport.getClosedAfterFinishedDelta());
            report.setConfigProfileIdentifier(siteReport.getConfigProfileIdentifier());
            report.setConfigProfileIdentifierTls13(siteReport.getConfigProfileIdentifierTls13());
            
            for(String key : siteReport.getResultMap().keySet()) {
                report.putResult(TlsAnalyzedProperty.valueOf(key), siteReport.getResultMap().get(key));
            }
            
            return report;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public ClientHelloMessage getReceivedClientHello() {
        return receivedClientHello;
    }
    
    public List<NamedGroup> getClientHelloKeyShareGroups() {
        List<NamedGroup> keyShareGroups = new LinkedList<>();
        if(receivedClientHello != null && receivedClientHello.containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage keyshare = receivedClientHello.getExtension(KeyShareExtensionMessage.class);
            for(KeyShareEntry ksEntry : keyshare.getKeyShareList()) {
                keyShareGroups.add(ksEntry.getGroupConfig());
            }
        }
        return keyShareGroups;
    }
    
    @Override
    public List<NamedGroup> getSupportedNamedGroups() {
        //We limit the tests to EC Named Groups for now
        return super.getSupportedNamedGroups().stream().filter(NamedGroup::isCurve).collect(Collectors.toList());
    }
    
    @Override
    public List<NamedGroup> getSupportedTls13Groups() {
        //We limit the tests to EC Named Groups for now
        return super.getSupportedTls13Groups().stream().filter(NamedGroup::isCurve).collect(Collectors.toList());
    }
    
    public List<NamedGroup> getSupportedFfdheNamedGroups() {
        //We only use these for FFDHE RFC tests for now
        return super.getSupportedNamedGroups().stream().filter(NamedGroup::isDhGroup).collect(Collectors.toList());
    }
    
    public List<NamedGroup> getSupportedTls13FfdheNamedGroups() {
        //We limit the tests to EC Named Groups for now
        return super.getSupportedTls13Groups().stream().filter(NamedGroup::isDhGroup).collect(Collectors.toList());
    }
    
    public List<NamedGroup> getClientHelloNamedGroups() {
        if(receivedClientHello != null && receivedClientHello.containsExtension(ExtensionType.ELLIPTIC_CURVES)) {
            return NamedGroup.namedGroupsFromByteArray(receivedClientHello.getExtension(EllipticCurvesExtensionMessage.class).getSupportedGroups().getValue());
        }
        return new LinkedList<>();
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
