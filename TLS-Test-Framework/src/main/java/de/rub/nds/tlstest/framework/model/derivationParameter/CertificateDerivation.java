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
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.scanner.core.probe.result.IntegerResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.helper.CertificateConfigChainValue;
import de.rub.nds.tlstest.framework.utils.X509CertificateChainProvider;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.*;
import java.util.stream.Collectors;

/** Selects CertificateKeyPairs for the IPM */
public class CertificateDerivation extends TlsDerivationParameter<CertificateConfigChainValue> {

    private final int MIN_RSA_SIG_KEY_LEN;
    private final int MIN_RSA_KEY_LEN;
    private final int MIN_DSS_KEY_LEN;
    private final boolean ALLOW_DSS = true;

    public CertificateDerivation() {
        super(TlsParameterType.CERTIFICATE, CertificateConfigChainValue.class);
        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG)
                == TestResults.TRUE) {
            MIN_RSA_SIG_KEY_LEN =
                    ((IntegerResult)
                                    TestContext.getInstance()
                                            .getFeatureExtractionResult()
                                            .getResult(
                                                    TlsAnalyzedProperty
                                                            .SERVER_CERT_MIN_KEY_SIZE_RSA_SIG))
                            .getValue();
        } else {
            MIN_RSA_SIG_KEY_LEN = 0;
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA)
                == TestResults.TRUE) {
            MIN_RSA_KEY_LEN =
                    ((IntegerResult)
                                    TestContext.getInstance()
                                            .getFeatureExtractionResult()
                                            .getResult(
                                                    TlsAnalyzedProperty
                                                            .SERVER_CERT_MIN_KEY_SIZE_RSA))
                            .getValue();
        } else {
            MIN_RSA_KEY_LEN = 0;
        }

        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS)
                == TestResults.TRUE) {
            MIN_DSS_KEY_LEN =
                    ((IntegerResult)
                                    TestContext.getInstance()
                                            .getFeatureExtractionResult()
                                            .getResult(
                                                    TlsAnalyzedProperty
                                                            .SERVER_CERT_MIN_KEY_SIZE_DSS))
                            .getValue();
        } else {
            MIN_DSS_KEY_LEN = 0;
        }
    }

    public CertificateDerivation(CertificateConfigChainValue certChainConfig) {
        this();
        setSelectedValue(certChainConfig);
    }

    public List<DerivationParameter<Config, CertificateConfigChainValue>>
            getApplicableCertificateConfigs(
                    TestContext context, DerivationScope scope, boolean allowUnsupportedPkGroups) {

        List<CertificateConfigChainValue> certConfigs =
                X509CertificateChainProvider.getCertificateChainConfigs();
        return certConfigs.stream()
                .filter(
                        certChainConfig ->
                                certMatchesAnySupportedCipherSuite(certChainConfig, scope))
                .filter(this::filterRsaKeySize)
                .filter(this::filterDssKeySize)
                .filter(this::filterDssSignedCerts)
                .filter(
                        certChainConfig ->
                                filterEcdsaPublicKeyGroups(
                                        certChainConfig, context, allowUnsupportedPkGroups))
                .filter(certChainConfig -> filterTls13Groups(certChainConfig, scope))
                .map(CertificateDerivation::new)
                .collect(Collectors.toList());
    }

    private boolean filterRsaKeySize(List<X509CertificateConfig> configs) {
        X509CertificateConfig config = configs.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        return config.getPublicKeyType() != X509PublicKeyType.RSA
                || (config.getRsaModulus().bitLength() >= MIN_RSA_KEY_LEN
                        && config.getRsaModulus().bitLength() >= MIN_RSA_SIG_KEY_LEN);
    }

    private boolean filterDssSignedCerts(List<X509CertificateConfig> configs) {
        X509CertificateConfig config = configs.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        return config.getDefaultSignatureAlgorithm().getSignatureAlgorithm()
                        != SignatureAlgorithm.DSA
                || ALLOW_DSS;
    }

    private boolean filterDssKeySize(List<X509CertificateConfig> configs) {
        X509CertificateConfig config = configs.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        return config.getPublicKeyType() != X509PublicKeyType.DSA
                || config.getDsaPrimeQ().bitLength() >= MIN_DSS_KEY_LEN;
    }

    private boolean filterEcdsaPublicKeyGroups(
            List<X509CertificateConfig> configs,
            TestContext context,
            boolean allowUnsupportedPkGroups) {
        X509CertificateConfig config = configs.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        return !config.getPublicKeyType().isEc()
                || context.getFeatureExtractionResult()
                        .getNamedGroups()
                        .contains(
                                NamedGroup.convertFromX509NamedCurve(
                                        config.getDefaultSubjectNamedCurve()))
                || allowUnsupportedPkGroups;
    }

    private boolean filterTls13Groups(List<X509CertificateConfig> configs, DerivationScope scope) {
        X509CertificateConfig config = configs.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        if (!TlsParameterIdentifierProvider.isTls13Test(scope)) {
            return true;
        }
        if (config.getPublicKeyType().isEc()) {
            return NamedGroup.convertFromX509NamedCurve(config.getDefaultSubjectNamedCurve())
                    .isTls13();
        }
        if (config.getPublicKeyType() == X509PublicKeyType.DH) {
            // TODO: Find a nicer way to retrieve the named group from the DH parameters
            return Arrays.stream(NamedGroup.values())
                    .filter(NamedGroup::isDhGroup)
                    .filter(candidate -> Objects.nonNull(candidate.getGroupParameters()))
                    .filter(
                            candidate ->
                                    ((FfdhGroupParameters) candidate.getGroupParameters())
                                                    .getModulus()
                                                    .equals(config.getDhModulus())
                                            && ((FfdhGroupParameters)
                                                            candidate.getGroupParameters())
                                                    .getGenerator()
                                                    .equals(config.getDhGenerator()))
                    .findFirst()
                    .map(NamedGroup::isTls13)
                    .orElse(true);
        }
        return true;
    }

    private boolean certMatchesAnySupportedCipherSuite(
            List<X509CertificateConfig> configs, DerivationScope scope) {
        Set<CipherSuite> cipherSuites;
        X509CertificateConfig config = configs.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        if (!TlsParameterIdentifierProvider.isTls13Test(scope)) {
            cipherSuites = TestContext.getInstance().getFeatureExtractionResult().getCipherSuites();
            return cipherSuites.stream()
                    .map(AlgorithmResolver::getSuiteableLeafCertificateKeyType)
                    .flatMap(Arrays::stream)
                    .anyMatch(kt -> Objects.equals(kt, config.getPublicKeyType()));
        } else {
            switch (config.getPublicKeyType()) {
                case ECDH_ONLY:
                case ECDH_ECDSA:
                case RSA:
                    return true;
                default:
                    return false;
            }
        }
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        config.setAutoAdjustCertificate(false);
        config.setCertificateChainConfig((List<X509CertificateConfig>) getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (!TlsParameterIdentifierProvider.isTls13Test(scope)) {
            condConstraints.add(getCertPkTypeMustMatchCipherSuiteConstraint());
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
                                    X509CertificateConfig selectedCertConfig =
                                            (X509CertificateConfig)
                                                    certificateDerivation
                                                            .getSelectedValue()
                                                            .get(
                                                                    X509CertificateChainProvider
                                                                            .LEAF_CERT_INDEX);
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    X509PublicKeyType[] requiredCertKeyTypes =
                                            AlgorithmResolver.getSuiteableLeafCertificateKeyType(
                                                    selectedCipherSuite);
                                    X509PublicKeyType actualCertKeyType =
                                            selectedCertConfig.getPublicKeyType();
                                    return Arrays.stream(requiredCertKeyTypes)
                                            .anyMatch(kt -> kt == actualCertKeyType);
                                }));
    }

    @Override
    public String toString() {
        X509CertificateConfig certConfig =
                (X509CertificateConfig)
                        getSelectedValue().get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        StringJoiner joiner = new StringJoiner(",");
        joiner.add("Public Key Type: " + certConfig.getPublicKeyType().name());
        if (certConfig.getPublicKeyType().isEc()) {
            joiner.add("Named Curve: " + certConfig.getDefaultSubjectNamedCurve().name());
        } else if (certConfig.getPublicKeyType().name().contains("RSA")) {
            joiner.add("RSA Modulus: " + certConfig.getRsaModulus().bitLength());
        }
        joiner.add(
                "Certificate Signature Type: " + certConfig.getDefaultSignatureAlgorithm().name());
        return joiner.toString();
    }

    @Override
    public List<DerivationParameter<Config, CertificateConfigChainValue>> getParameterValues(
            DerivationScope derivationScope) {
        return getApplicableCertificateConfigs(context, derivationScope, false);
    }

    @Override
    protected TlsDerivationParameter<CertificateConfigChainValue> generateValue(
            CertificateConfigChainValue selectedValue) {
        return new CertificateDerivation(selectedValue);
    }

    public X509CertificateConfig getLeafConfig() {
        return (X509CertificateConfig)
                getSelectedValue().get(X509CertificateChainProvider.LEAF_CERT_INDEX);
    }
}
