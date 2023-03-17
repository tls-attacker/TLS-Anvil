/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;

/** Selects CertificateKeyPairs for the IPM */
public class CertificateDerivation extends DerivationParameter<CertificateKeyPair> {

    private final int MIN_RSA_KEY_LEN =
            TestContext.getInstance().getSiteReport().getMinimumRsaCertKeySize();
    private final int MIN_DSS_KEY_LEN =
            TestContext.getInstance().getSiteReport().getMinimumDssCertKeySize();
    private final boolean ALLOW_DSS = true;

    public CertificateDerivation() {
        super(DerivationType.CERTIFICATE, CertificateKeyPair.class);
    }

    public CertificateDerivation(CertificateKeyPair certKeyPair) {
        this();
        setSelectedValue(certKeyPair);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        return getApplicableCertificates(context, scope, false);
    }

    public List<DerivationParameter> getApplicableCertificates(
            TestContext context, DerivationScope scope, boolean allowUnsupportedPkGroups) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        CertificateByteChooser.getInstance().getCertificateKeyPairList().stream()
                .filter(cert -> certMatchesAnySupportedCipherSuite(cert, scope))
                .filter(cert -> filterRsaKeySize(cert))
                .filter(cert -> filterDssKeySize(cert))
                .filter(cert -> filterDssSignedCerts(cert))
                .filter(cert -> filterEcdsaPublicKeyGroups(cert, context, allowUnsupportedPkGroups))
                .filter(cert -> filterTls13Groups(cert, scope))
                .forEach(cert -> parameterValues.add(new CertificateDerivation(cert)));
        return parameterValues;
    }

    private boolean filterRsaKeySize(CertificateKeyPair cert) {
        return cert.getCertPublicKeyType() != CertificateKeyType.RSA
                || cert.getPublicKey().keySize() >= MIN_RSA_KEY_LEN;
    }

    private boolean filterDssSignedCerts(CertificateKeyPair cert) {
        return cert.getCertSignatureType() != CertificateKeyType.DSS || ALLOW_DSS;
    }

    private boolean filterDssKeySize(CertificateKeyPair cert) {
        return cert.getCertPublicKeyType() != CertificateKeyType.DSS
                || cert.getPublicKey().keySize() >= MIN_DSS_KEY_LEN;
    }

    private boolean filterEcdsaPublicKeyGroups(
            CertificateKeyPair cert, TestContext context, boolean allowUnsupportedPkGroups) {
        return (cert.getPublicKeyGroup() == null
                        || context.getSiteReport()
                                .getSupportedNamedGroups()
                                .contains(cert.getPublicKeyGroup()))
                || allowUnsupportedPkGroups;
    }

    private boolean filterTls13Groups(CertificateKeyPair cert, DerivationScope scope) {
        return cert.getPublicKeyGroup() == null
                || !scope.isTls13Test()
                || cert.getPublicKeyGroup().isTls13();
    }

    private boolean certMatchesAnySupportedCipherSuite(
            CertificateKeyPair cert, DerivationScope scope) {
        Set<CipherSuite> cipherSuites;
        if (!scope.isTls13Test()) {
            cipherSuites = TestContext.getInstance().getSiteReport().getCipherSuites();
            return cipherSuites.stream()
                    .anyMatch(
                            cipherSuite ->
                                    AlgorithmResolver.getCertificateKeyType(cipherSuite)
                                                    == cert.getCertPublicKeyType()
                                            || isEcdhEcdsaAmbiguity(cipherSuite, cert));
        } else {
            switch (cert.getCertPublicKeyType()) {
                case ECDH:
                case ECDSA:
                case RSA:
                    return true;
                default:
                    return false;
            }
        }
    }

    private static boolean isEcdhEcdsaAmbiguity(CipherSuite cipherSuite, CertificateKeyPair cert) {
        return cert.getCertPublicKeyType() == CertificateKeyType.ECDH
                && AlgorithmResolver.getCertificateKeyType(cipherSuite) == CertificateKeyType.ECDSA;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAutoSelectCertificate(false);
        config.setDefaultExplicitCertificateKeyPair(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (!scope.isTls13Test()) {
            if (ConstraintHelper.multipleCertPublicKeyTypesModeled(scope)
                    || ConstraintHelper.cipherSuitesWithDifferentCertPublicKeyRequirementsModeled(
                            scope)) {
                condConstraints.add(getCertPkTypeMustMatchCipherSuiteConstraint());
            }
        }
        return condConstraints;
    }

    private ConditionalConstraint getCertPkTypeMustMatchCipherSuiteConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                this.getType().name(), DerivationType.CIPHERSUITE.name())
                        .by(
                                (CertificateDerivation certificateDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    CertificateKeyPair selectedCertKeyPair =
                                            certificateDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    CertificateKeyType requiredCertKeyType =
                                            AlgorithmResolver.getCertificateKeyType(
                                                    selectedCipherSuite);
                                    return selectedCertKeyPair.getCertPublicKeyType()
                                            == requiredCertKeyType;
                                }));
    }

    @Override
    public String jsonValue() {
        CertificateKeyPair certKeyPair = getSelectedValue();
        StringJoiner joiner = new StringJoiner(",");
        joiner.add("Public Key Type: " + certKeyPair.getCertPublicKeyType().name());
        joiner.add("Public Key Size: " + certKeyPair.getPublicKey().keySize());
        if (certKeyPair.getPublicKeyGroup() != null) {
            joiner.add("Public Key Group: " + certKeyPair.getPublicKeyGroup());
        }
        joiner.add("Certificate Signature Type: " + certKeyPair.getCertSignatureType().name());
        if (certKeyPair.getSignatureGroup() != null) {
            joiner.add("Signature Key Group: " + certKeyPair.getSignatureGroup());
        }
        return joiner.toString();
    }
}
