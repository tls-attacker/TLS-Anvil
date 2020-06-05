package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import org.bouncycastle.crypto.tls.Certificate;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class TestSiteReport implements Serializable {

    //Version
    private List<ProtocolVersion> versions = null;

    //Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;

    //Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    //Ciphers
    private Set<CipherSuite> cipherSuites = null;
    private List<CipherSuite> supportedTls13CipherSuites = null;

    private List<VersionSuiteListPair> versionSuiteListPairs = null;

    public TestSiteReport(SiteReport report) {
        this.versions = report.getVersions();

        this.supportedExtensions = report.getSupportedExtensions();
        this.supportedNamedGroups = report.getSupportedNamedGroups();
        this.supportedTls13Groups = report.getSupportedTls13Groups();
        this.supportedSignatureAndHashAlgorithms = report.getSupportedSignatureAndHashAlgorithms();

        this.supportedCompressionMethods = report.getSupportedCompressionMethods();

        this.cipherSuites = report.getCipherSuites();
        this.supportedTls13CipherSuites = report.getSupportedTls13CipherSuites();
        this.versionSuiteListPairs = report.getVersionSuitePairs();
    }

    public SiteReport getSiteReport() {
        SiteReport report = new SiteReport("", new ArrayList<>());

        report.setVersions(this.getVersions());

        report.setSupportedExtensions(this.getSupportedExtensions());
        report.setSupportedNamedGroups(this.getSupportedNamedGroups());
        report.setSupportedTls13Groups(this.getSupportedTls13Groups());
        report.setSupportedSignatureAndHashAlgorithms(this.getSupportedSignatureAndHashAlgorithms());

        report.setSupportedCompressionMethods(this.getSupportedCompressionMethods());

        report.setCipherSuites(this.getCipherSuites());
        report.setSupportedTls13CipherSuites(this.getSupportedTls13CipherSuites());
        report.setVersionSuitePairs(this.getVersionSuiteListPairs());

        return report;
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public List<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public void setSupportedNamedGroups(List<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public List<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    public void setSupportedTls13Groups(List<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }


    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<CipherSuite> getSupportedTls13CipherSuites() {
        return supportedTls13CipherSuites;
    }

    public void setSupportedTls13CipherSuites(List<CipherSuite> supportedTls13CipherSuites) {
        this.supportedTls13CipherSuites = supportedTls13CipherSuites;
    }

    public List<VersionSuiteListPair> getVersionSuiteListPairs() {
        return versionSuiteListPairs;
    }

    public void setVersionSuiteListPairs(List<VersionSuiteListPair> versionSuiteListPairs) {
        this.versionSuiteListPairs = versionSuiteListPairs;
    }
}
