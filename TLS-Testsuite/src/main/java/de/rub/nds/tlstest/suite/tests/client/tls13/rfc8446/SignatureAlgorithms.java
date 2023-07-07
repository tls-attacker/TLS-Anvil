/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ExplicitModelingConstraints;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;

import de.rub.nds.anvilcore.annotation.ExplicitModelingConstraints;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.2.3. Signature Algorithms")
@ClientTest
public class SignatureAlgorithms extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getFeatureExtractionResult()
                .getSupportedVersions()
                .contains(ProtocolVersion.TLS12)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("TLS 1.2 is not supported by the server.");
    }

    @AnvilTest(
            description =
                    "Note that TLS 1.2 defines this extension differently.  TLS 1.3 "
                            + "implementations willing to negotiate TLS 1.2 MUST behave in "
                            + "accordance with the requirements of [RFC5246] when negotiating that "
                            + "version. In particular:[...]"
                            + "ECDSA signature schemes align with TLS 1.2's ECDSA hash/signature "
                            + "pairs.  However, the old semantics did not constrain the signing "
                            + "curve.  If TLS 1.2 is negotiated, implementations MUST be prepared "
                            + "to accept a signature that uses any curve that they advertised in "
                            + "the \"supported_groups\" extension.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ExplicitModelingConstraints(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getMixedEccHashLengthPairs")
    @DynamicValueConstraints(
            affectedIdentifiers = {
                "CIPHER_SUITE",
                "CERTIFICATE",
                "SIG_HASH_ALGORIHTM"
            },
            methods = {"isEcdsaCipherSuite", "isApplicableEcdsaCert", "isTls13SigHash"})
    @Tag("new")
    public void acceptsMixedCurveHashLengthInTls12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(
            description =
                    "Note that TLS 1.2 defines this extension differently.  TLS 1.3 "
                            + "implementations willing to negotiate TLS 1.2 MUST behave in "
                            + "accordance with the requirements of [RFC5246] when negotiating that "
                            + "version. In particular:[...]"
                            + "Implementations that advertise support for RSASSA-PSS (which is "
                            + "mandatory in TLS 1.3) MUST be prepared to accept a signature using "
                            + "that scheme even when TLS 1.2 is negotiated.  In TLS 1.2, "
                            + "RSASSA-PSS is used with RSA cipher suites.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @DynamicValueConstraints(
            affectedIdentifiers = {"CIPHER_SUITE", "SIG_HASH_ALGORIHTM"},
            methods = {"isRsaSignatureCipherSuite", "isRsaPssAlgorithm"})
    @Tag("new")
    public void supportsRsaPssInTls12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }

    @Test
    @TestDescription(
            "Note that TLS 1.2 defines this extension differently.  TLS 1.3 "
                    + "implementations willing to negotiate TLS 1.2 MUST behave in "
                    + "accordance with the requirements of [RFC5246] when negotiating that "
                    + "version. In particular:[...]"
                    + "In TLS 1.2, the extension contained hash/signature pairs.  The "
                    + "pairs are encoded in two octets, so SignatureScheme values have "
                    + "been allocated to align with TLS 1.2's encoding.  Some legacy "
                    + "pairs are left unallocated.  These algorithms are deprecated as of "
                    + "TLS 1.3.  They MUST NOT be offered or negotiated by any "
                    + "implementation.  In particular, MD5 [SLOTH], SHA-224, and DSA "
                    + "MUST NOT be used.")
    @Tag("new")
    public void noDeprecatedAlgorithmsOffered() {
        ClientFeatureExtractionResult extractionResult =
                (ClientFeatureExtractionResult) context.getFeatureExtractionResult();
        if (extractionResult.getAdvertisedSignatureAndHashAlgorithms() != null) {
            List<SignatureAndHashAlgorithm> deprecatedOffered = new LinkedList();
            extractionResult
                    .getAdvertisedSignatureAndHashAlgorithms()
                    .forEach(
                            algorithm -> {
                                if (algorithm.getSignatureAlgorithm() == SignatureAlgorithm.DSA
                                        || algorithm.getHashAlgorithm() == HashAlgorithm.MD5
                                        || algorithm.getHashAlgorithm() == HashAlgorithm.SHA224
                                        || algorithm.getHashAlgorithm() == HashAlgorithm.SHA1) {
                                    deprecatedOffered.add(algorithm);
                                }
                            });

            assertTrue(
                    "Client offered deprecated algorithms: "
                            + deprecatedOffered.stream()
                                    .map(Object::toString)
                                    .collect(Collectors.joining(",")),
                    deprecatedOffered.isEmpty());
        }
    }

    public boolean isTls13SigHash(SignatureAndHashAlgorithm algorithmPair) {
        return algorithmPair != null && algorithmPair.suitedForSigningTls13Messages();
    }

    public boolean isEcdsaCipherSuite(CipherSuite cipherSuite) {
        return AlgorithmResolver.getCertificateKeyType(cipherSuite) == CertificateKeyType.ECDSA;
    }

    public boolean isApplicableEcdsaCert(CertificateKeyPair keyPair) {
        return (keyPair.getCertPublicKeyType() == CertificateKeyType.ECDSA
                        || keyPair.getCertPublicKeyType() == CertificateKeyType.ECDH)
                && (keyPair.getPublicKeyGroup() == NamedGroup.SECP256R1
                        || keyPair.getPublicKeyGroup() == NamedGroup.SECP384R1
                        || keyPair.getPublicKeyGroup() == NamedGroup.SECP521R1);
    }

    public boolean isRsaSignatureCipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isEphemeral()
                && AlgorithmResolver.getCertificateKeyType(cipherSuite) != null
                && AlgorithmResolver.getCertificateKeyType(cipherSuite) == CertificateKeyType.RSA;
    }

    public boolean isRsaPssAlgorithm(SignatureAndHashAlgorithm algorithmPair) {
        return algorithmPair != null
                && algorithmPair.getSignatureAlgorithm().name().contains("PSS");
    }

    public List<ConditionalConstraint> getMixedEccHashLengthPairs(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        condConstraints.addAll(SigAndHashDerivation.getSharedDefaultConditionalConstraints(scope));
        condConstraints.addAll(SigAndHashDerivation.getDefaultPreTls13Constraints(scope));
        condConstraints.add(getHashSizeMustNotMatchEcdsaPkSizeConstraint());
        return condConstraints;
    }

    private ConditionalConstraint getHashSizeMustNotMatchEcdsaPkSizeConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CERTIFICATE));

        // TLS 1.3 specifies explicit curves for hash functions in ECDSA
        // e.g ecdsa_secp256r1_sha256
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CERTIFICATE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CertificateDerivation certificateDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null) {
                                        CertificateKeyPair certKeyPair =
                                                certificateDerivation.getSelectedValue();
                                        HashAlgorithm hashAlgo =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getHashAlgorithm();

                                        if ((certKeyPair.getPublicKeyGroup() == NamedGroup.SECP256R1
                                                        && hashAlgo != HashAlgorithm.SHA256)
                                                || (certKeyPair.getPublicKeyGroup()
                                                                == NamedGroup.SECP384R1
                                                        && hashAlgo != HashAlgorithm.SHA384)
                                                || (certKeyPair.getPublicKeyGroup()
                                                                == NamedGroup.SECP521R1
                                                        && hashAlgo != HashAlgorithm.SHA512)) {
                                            return true;
                                        }
                                    }
                                    return false;
                                }));
    }
}
