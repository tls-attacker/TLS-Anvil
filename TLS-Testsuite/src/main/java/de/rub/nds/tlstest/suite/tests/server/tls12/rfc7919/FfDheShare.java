/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7919;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
@Tag("dheshare")
public class FfDheShare extends Tls12Test {

    public ConditionEvaluationResult supportsNamedFfdheGroups() {
        if (!context.getFeatureExtractionResult().getFfdheNamedGroups().isEmpty()) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not support FFDHE Named Groups");
    }

    public ConditionEvaluationResult supportsDheCipherSuiteAndNamedGroups() {
        if (!context.getFeatureExtractionResult().getCipherSuites().stream()
                .anyMatch(
                        cipher ->
                                cipher.isRealCipherSuite()
                                        && cipher.isEphemeral()
                                        && AlgorithmResolver.getKeyExchangeAlgorithm(cipher)
                                                .isKeyExchangeDh())) {
            return supportsNamedFfdheGroups();
        }
        return ConditionEvaluationResult.disabled("Target does not support DHE Cipher Suites");
    }

    @AnvilTest(id = "7919-1GQ8w3rdqd")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
    @ManualConfig(identifiers = "FFDHE_SHARE_OUT_OF_BOUNDS")
    @KeyExchange(supported = KeyExchangeType.DH)
    public void shareOutOfBounds(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        DHClientKeyExchangeMessage cke = new DHClientKeyExchangeMessage();
        cke.prepareComputations();
        DHClientComputations computations = cke.getComputations();

        ShareOutOfBoundsDerivation share =
                parameterCombination.getParameter(ShareOutOfBoundsDerivation.class);
        switch (share.getSelectedValue()) {
            case SHARE_IS_ZERO:
                c.setDefaultClientDhPrivateKey(BigInteger.ZERO);
                c.setDefaultClientDhPublicKey(BigInteger.ZERO);
                break;
            case SHARE_IS_ONE:
                c.setDefaultClientDhPrivateKey(BigInteger.ZERO);
                c.setDefaultClientDhPublicKey(BigInteger.ONE);
                break;
            case SHARE_PLUS_P:
                // multiply modulus by 2^64
                // Chance that public share is below original p is 1/2^64
                // TODO: would be nice if we could always be above this bound, but only barely
                // i.e. share += p; but this would require us to already know p...
                computations.setModulus(Modifiable.shiftLeftBigInteger(64));
                break;
            default:
                throw new UnsupportedOperationException("Unknown type " + share.getSelectedValue());
        }

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsActions(
                new SendAction(cke),
                new SendAction(ActionOption.MAY_FAIL, new ChangeCipherSpecMessage()),
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        // accept both Illegal Parameter and Handshake Failure as RFC 8446 and
        // 7919 demand different alerts
        if (msg != null
                && !msg.getDescription()
                        .getValue()
                        .equals(AlertDescription.ILLEGAL_PARAMETER.getValue())) {
            Validator.testAlertDescription(
                    state, testCase, AlertDescription.HANDSHAKE_FAILURE, msg);
        }
    }

    @AnvilTest(id = "7919-pPnKVL1dfj")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @MethodCondition(method = "supportsDheCipherSuiteAndNamedGroups")
    @Tag("new")
    public void negotiatesNonFfdheIfNecessary(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddEllipticCurveExtension(true);
        config.setDefaultClientNamedGroups(context.getFeatureExtractionResult().getNamedGroups());
        context.getFeatureExtractionResult()
                .getCipherSuites()
                .forEach(
                        cipher -> {
                            if (cipher.isRealCipherSuite()
                                    && !AlgorithmResolver.getKeyExchangeAlgorithm(cipher)
                                            .isKeyExchangeDh()) {
                                config.getDefaultClientSupportedCipherSuites().add(cipher);
                            }
                        });

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello =
                workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        // make FFDHE group most preferred
        clientHello
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.insert(getUnsupportedNamedGroup(), 0));

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        assertNotEquals(
                "Server negotiated DHE cipher suite",
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue(),
                state.getTlsContext().getSelectedCipherSuite());
    }

    @AnvilTest(id = "7919-5qMeS9hJ7K")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @ExcludeParameter("NAMED_GROUP")
    @MethodCondition(method = "supportsNamedFfdheGroups")
    @Tag("new")
    public void abortsWhenGroupsDontOverlap(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddEllipticCurveExtension(true);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        clientHello
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(getUnsupportedNamedGroup()));

        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.INSUFFICIENT_SECURITY);
    }

    @AnvilTest(id = "7919-poUc9K3yfd")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getSupportedFfdheNamedGroups")
    @ManualConfig(identifiers = "NAMED_GROUP")
    @ExplicitModelingConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "getEmptyConstraintsList")
    @Tag("new")
    public void respectsOfferedGroups(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        NamedGroup ffdheGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        config.setDefaultClientNamedGroups(ffdheGroup);
        config.setAddEllipticCurveExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        State state = runner.execute(workflowTrace, config);
        Validator.executedAsPlanned(state, testCase);
        assertEquals(
                "Server did not respect the offered group",
                ffdheGroup,
                state.getTlsContext().getSelectedGroup());
    }

    @AnvilTest(id = "7919-stXkxYBEVU")
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @Tag("new")
    public void doesNotNegotiateDheCipherSuiteWhenNotOffered(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        ClientHelloMessage clientHello =
                workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        byte[] ffdheGroupBytes = new byte[0];
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isDhGroup()) {
                ffdheGroupBytes = ArrayConverter.concatenate(ffdheGroupBytes, group.getValue());
            }
        }
        // place FFDHE groups first
        clientHello
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.insert(ffdheGroupBytes, 0));

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        assertFalse(
                "Server selected an FFDHE cipher suite",
                AlgorithmResolver.getKeyExchangeAlgorithm(
                                state.getTlsContext().getSelectedCipherSuite())
                        .isKeyExchangeDh());
    }

    public List<DerivationParameter<Config, NamedGroup>> getSupportedFfdheNamedGroups(
            DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> parameterValues = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getFfdheNamedGroups()
                .forEach(group -> parameterValues.add(new NamedGroupDerivation(group)));
        return parameterValues;
    }

    public List<ConditionalConstraint> getEmptyConstraintsList(DerivationScope scope) {
        return new LinkedList<>();
    }

    private byte[] getUnsupportedNamedGroup() {
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isDhGroup()
                    && !context.getFeatureExtractionResult()
                            .getFfdheNamedGroups()
                            .contains(group)) {
                return group.getValue();
            }
        }

        // RFC 7919: [...] any FFDHE group (i.e., any codepoint between
        // 256 and 511, inclusive, even if unknown to the server)
        return new byte[] {0x1, (byte) 0xFF};
    }
}
