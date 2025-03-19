/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.helper.CertificateConfigChainValue;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.framework.utils.X509CertificateChainProvider;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

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

    @AnvilTest(id = "8446-qibaoRRFDr")
    @ModelFromScope(modelType = "CERTIFICATE")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ExplicitModelingConstraints(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getMixedEccHashLengthPairs")
    @DynamicValueConstraints(
            affectedIdentifiers = {"CIPHER_SUITE", "CERTIFICATE", "SIG_HASH_ALGORIHTM"},
            methods = {"isEcdsaCipherSuite", "isApplicableEcdsaCert", "isTls13SigHash"})
    @Tag("new")
    public void acceptsMixedCurveHashLengthInTls12(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        State state = runner.execute(workflowTrace, config);
        Validator.executedAsPlanned(state, testCase);
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
                                        X509CertificateConfig certConfig =
                                                certificateDerivation
                                                        .getSelectedValue()
                                                        .get(
                                                                X509CertificateChainProvider
                                                                        .LEAF_CERT_INDEX);
                                        HashAlgorithm hashAlgo =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getHashAlgorithm();
                                        if (!certConfig.getPublicKeyType().isEc()) {
                                            return false;
                                        }

                                        if ((certConfig.getDefaultSubjectNamedCurve()
                                                                == X509NamedCurve.SECP256R1
                                                        && hashAlgo != HashAlgorithm.SHA256)
                                                || (certConfig.getDefaultSubjectNamedCurve()
                                                                == X509NamedCurve.SECP384R1
                                                        && hashAlgo != HashAlgorithm.SHA384)
                                                || (certConfig.getDefaultSubjectNamedCurve()
                                                                == X509NamedCurve.SECP521R1
                                                        && hashAlgo != HashAlgorithm.SHA512)) {
                                            return true;
                                        }
                                    }
                                    return false;
                                }));
    }

    @AnvilTest(id = "8446-qNaBPZ4ofA")
    @ModelFromScope(modelType = "CERTIFICATE")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @DynamicValueConstraints(
            affectedIdentifiers = {"CIPHER_SUITE", "SIG_HASH_ALGORIHTM"},
            methods = {"isRsaSignatureCipherSuite", "isRsaPssAlgorithm"})
    @Tag("new")
    public void supportsRsaPssInTls12(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        State state = runner.execute(workflowTrace, config);
        Validator.executedAsPlanned(state, testCase);
    }

    @NonCombinatorialAnvilTest(id = "8446-5E3CVBTFdt")
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
                    deprecatedOffered.isEmpty(),
                    "Client offered deprecated algorithms: "
                            + deprecatedOffered.stream()
                                    .map(Object::toString)
                                    .collect(Collectors.joining(",")));
        }
    }

    public boolean isTls13SigHash(SignatureAndHashAlgorithm algorithmPair) {
        return algorithmPair != null && algorithmPair.suitedForSigningTls13Messages();
    }

    public boolean isEcdsaCipherSuite(CipherSuite cipherSuite) {
        return AlgorithmResolver.getRequiredSignatureAlgorithm(cipherSuite)
                == SignatureAlgorithm.ECDSA;
    }

    public boolean isApplicableEcdsaCert(CertificateConfigChainValue certChain) {
        X509CertificateConfig leafConfig =
                certChain.get(X509CertificateChainProvider.LEAF_CERT_INDEX);
        X509PublicKeyType pkType = leafConfig.getPublicKeyType();
        X509NamedCurve curve = leafConfig.getDefaultSubjectNamedCurve();
        return (pkType == X509PublicKeyType.ECDH_ECDSA || pkType == X509PublicKeyType.ECDH_ONLY)
                && (curve == X509NamedCurve.SECP256R1
                        || curve == X509NamedCurve.SECP384R1
                        || curve == X509NamedCurve.SECP521R1);
    }

    public boolean isRsaSignatureCipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isEphemeral()
                && cipherSuite.getKeyExchangeAlgorithm() != null
                && AlgorithmResolver.getRequiredSignatureAlgorithm(cipherSuite)
                        == SignatureAlgorithm.RSA_PKCS1;
    }

    public boolean isRsaPssAlgorithm(SignatureAndHashAlgorithm algorithmPair) {
        return algorithmPair != null
                && algorithmPair.getSignatureAlgorithm().name().contains("PSS");
    }
}
