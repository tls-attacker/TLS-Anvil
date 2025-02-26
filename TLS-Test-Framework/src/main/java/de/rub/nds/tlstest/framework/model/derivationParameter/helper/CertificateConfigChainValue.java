package de.rub.nds.tlstest.framework.model.derivationParameter.helper;

import de.rub.nds.x509attacker.config.X509CertificateConfig;
import java.util.LinkedList;
import java.util.List;

public class CertificateConfigChainValue extends LinkedList<X509CertificateConfig> {
    public CertificateConfigChainValue(List<X509CertificateConfig> certificates) {
        super(certificates);
    }

    public static List<CertificateConfigChainValue> fromCertificateConfigs(
            List<List<X509CertificateConfig>> configLists) {
        List<CertificateConfigChainValue> certificateLists = new LinkedList<>();
        for (List<X509CertificateConfig> configList : configLists) {
            certificateLists.add(new CertificateConfigChainValue(configList));
        }
        return certificateLists;
    }
}
