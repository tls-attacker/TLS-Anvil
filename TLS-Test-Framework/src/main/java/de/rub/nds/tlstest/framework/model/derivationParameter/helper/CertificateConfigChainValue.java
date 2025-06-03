package de.rub.nds.tlstest.framework.model.derivationParameter.helper;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlstest.framework.utils.X509CertificateChainProvider;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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

    @JsonValue
    public Map<String, Object> jsonObject() {
        Map<String, Object> res = new HashMap<>();
        // root type
        X509CertificateConfig root = get(1);
        res.put("ROOT", root.getPublicKeyType());
        X509CertificateConfig leaf = get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        Map<String, Object> leafRes = new HashMap<>();
        leafRes.put("keyType", leaf.getPublicKeyType());
        switch (leaf.getPublicKeyType()) {
            case ECDH_ECDSA:
                leafRes.put("group", leaf.getDefaultSubjectNamedCurve());
                break;
            case DH:
                leafRes.put(
                        "group", recognizeNamedGroup(leaf.getDhGenerator(), leaf.getDhModulus()));
                break;
            case DSA:
                break;
            default: // RSA
                leafRes.put("keySize", leaf.getRsaModulus().bitLength());
        }
        res.put("LEAF", leafRes);
        return res;
    }

    public String recognizeNamedGroup(BigInteger generator, BigInteger modulus) {
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isDhGroup()) {
                FfdhGroupParameters ffdhGroup = (FfdhGroupParameters) group.getGroupParameters();
                if (generator.equals(ffdhGroup.getGenerator())
                        && modulus.equals(ffdhGroup.getModulus())) {
                    return group.name();
                }
            }
        }
        return "Custom Group";
    }
}
