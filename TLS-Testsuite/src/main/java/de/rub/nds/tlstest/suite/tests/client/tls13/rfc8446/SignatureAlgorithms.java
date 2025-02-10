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
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
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
}
