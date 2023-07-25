/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.scanner.core.constants.NumericResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;

/** Selects CertificateKeyPairs for the IPM */
public class CertificateDerivation extends TlsDerivationParameter<CertificateKeyPair> {

    private final int MIN_RSA_SIG_KEY_LEN;
    private final int MIN_RSA_KEY_LEN;
    private final int MIN_DSS_KEY_LEN;
    private final boolean ALLOW_DSS = true;

    public CertificateDerivation() {
        super(TlsParameterType.CERTIFICATE, CertificateKeyPair.class);
        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG)
                == TestResults.TRUE) {
            MIN_RSA_SIG_KEY_LEN =
                    ((NumericResult)
                                    TestContext.getInstance()
                                            .getFeatureExtractionResult()
                                            .getResult(
                                                    TlsAnalyzedProperty
                                                            .SERVER_CERT_MIN_KEY_SIZE_RSA_SIG))
                            .getValue()
                            .intValue();
        } else {
            MIN_RSA_SIG_KEY_LEN = 0;
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA)
                == TestResults.TRUE) {
            MIN_RSA_KEY_LEN =
                    ((NumericResult)
                                    TestContext.getInstance()
                                            .getFeatureExtractionResult()
                                            .getResult(
                                                    TlsAnalyzedProperty
                                                            .SERVER_CERT_MIN_KEY_SIZE_RSA))
                            .getValue()
                            .intValue();
        } else {
            MIN_RSA_KEY_LEN = 0;
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS)
                == TestResults.TRUE) {
            MIN_DSS_KEY_LEN =
                    ((NumericResult)
                                    TestContext.getInstance()
                                            .getFeatureExtractionResult()
                                            .getResult(
                                                    TlsAnalyzedProperty
                                                            .SERVER_CERT_MIN_KEY_SIZE_DSS))
                            .getValue()
                            .intValue();
        } else {
            MIN_DSS_KEY_LEN = 0;
        }
    }

    public CertificateDerivation(CertificateKeyPair certKeyPair) {
        this();
        setSelectedValue(certKeyPair);
    }

    public List<DerivationParameter<TlsAnvilConfig, CertificateKeyPair>> getApplicableCertificates(
            TestContext context, DerivationScope scope, boolean allowUnsupportedPkGroups) {
        List<DerivationParameter<TlsAnvilConfig, CertificateKeyPair>> parameterValues =
                new LinkedList<>();
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
                || (cert.getPublicKey().keySize() >= MIN_RSA_KEY_LEN
                        && cert.getPublicKey().keySize() >= MIN_RSA_SIG_KEY_LEN);
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
                        || context.getFeatureExtractionResult()
                                .getNamedGroups()
                                .contains(cert.getPublicKeyGroup()))
                || allowUnsupportedPkGroups;
    }

    private boolean filterTls13Groups(CertificateKeyPair cert, DerivationScope scope) {
        return cert.getPublicKeyGroup() == null
                || !ConstraintHelper.isTls13Test(scope)
                || cert.getPublicKeyGroup().isTls13();
    }

    private boolean certMatchesAnySupportedCipherSuite(
            CertificateKeyPair cert, DerivationScope scope) {
        Set<CipherSuite> cipherSuites;
        if (!ConstraintHelper.isTls13Test(scope)) {
            cipherSuites = TestContext.getInstance().getFeatureExtractionResult().getCipherSuites();
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
    public void applyToConfig(TlsAnvilConfig config, DerivationScope derivationScope) {
        config.getTlsConfig().setAutoSelectCertificate(false);
        config.getTlsConfig().setDefaultExplicitCertificateKeyPair(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (!ConstraintHelper.isTls13Test(scope)) {
            if (ConstraintHelper.multipleCertPublicKeyTypesModeled(scope)
                    || ConstraintHelper.cipherSuitesWithDifferentCertPublicKeyRequirementsModeled(
                            scope)) {
                condConstraints.add(getCertPkTypeMustMatchCipherSuiteConstraint());
            }
        }
        return condConstraints;
    }

    private ConditionalConstraint getCertPkTypeMustMatchCipherSuiteConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CIPHER_SUITE.name())
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
    public String toString() {
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

    @Override
    public List<DerivationParameter<TlsAnvilConfig, CertificateKeyPair>> getParameterValues(
            DerivationScope derivationScope) {
        return getApplicableCertificates(context, derivationScope, false);
    }

    @Override
    protected TlsDerivationParameter<CertificateKeyPair> generateValue(
            CertificateKeyPair selectedValue) {
        return new CertificateDerivation(selectedValue);
    }
}
