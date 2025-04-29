/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7919;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
@Tag("dheshare")
public class FfDheShare extends Tls12Test {

    public ConditionEvaluationResult supportsFfdheAndEcNamedGroups() {
        if (!context.getFeatureExtractionResult().getFfdheNamedGroups().isEmpty()
                && context.getFeatureExtractionResult().getCipherSuites().stream()
                        .anyMatch(
                                cipher ->
                                        cipher.isRealCipherSuite()
                                                && AlgorithmResolver.getKeyExchangeAlgorithm(cipher)
                                                        .isKeyExchangeEcdh())) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled(
                "Target does not support both FFDHE and EC NamedGroups");
    }

    @AnvilTest(id = "7919-vE2y2kZU5J")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    public void shareOutOfBounds(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.addTlsActions(
                new SendAction(ActionOption.MAY_FAIL, new ServerHelloDoneMessage()),
                new ReceiveAction(new AlertMessage()));
        DHEServerKeyExchangeMessage SKE =
                (DHEServerKeyExchangeMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        byte[] publicShare = c.getDefaultServerEphemeralDhPublicKey().toByteArray();
        SKE.setPublicKey(publicShare);
        SKE.getPublicKey().addModification(new ByteArrayExplicitValueModification(publicShare));

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

    @NonCombinatorialAnvilTest(id = "7919-D3SJNRC99x")
    @MethodCondition(method = "supportsFfdheAndEcNamedGroups")
    @Tag("new")
    public void listsCurvesAndFfdheCorrectly() {
        // we always test for duplicate extensions anyway
        assertFalse(
                context.getFeatureExtractionResult().getNamedGroups().isEmpty(),
                "Client offered EC Cipher Suites and FFDHE groups but no EC Named Groups");
    }

    @AnvilTest(id = "7919-ZZzQLMYM3L")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getSupportedFfdheNamedGroups")
    @ManualConfig(identifiers = "NAMED_GROUP")
    @ExplicitModelingConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "getEmptyConstraintsList")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @Tag("new")
    public void supportsOfferedFfdheGroup(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        NamedGroup ffdheGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        config.setDefaultServerNamedGroups(ffdheGroup);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        assertEquals(
                ffdheGroup,
                state.getTlsContext().getSelectedGroup(),
                "Invalid NamedGroup set in context, expected "
                        + ffdheGroup
                        + " but was "
                        + state.getTlsContext().getSelectedGroup());
    }

    @AnvilTest(id = "7919-64FAvRFA4A")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @ExcludeParameter("NAMED_GROUP")
    @Tag("new")
    public void performsRequiredSecurityCheck(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        // 767 bits "safe prime"
        BigInteger unsafeSafePrime =
                new BigInteger(
                        "7030affcfe478388a7b6e16019c66524d69e231c4b556d32d530f636f402be0afb0dbc8529e955c3b2254782bfec749c1e751a3d4bdbaa9505cb6f5cd7945e307c846f714ce98b805c6f90ef06fc58f853e316417df7f8189af7b9e9c3e5abb3",
                        16);
        BigInteger generator = new BigInteger("2", 16);

        config.setDefaultServerNamedGroups(new LinkedList<>());
        config.setDefaultServerEphemeralDhGenerator(generator);
        config.setDefaultServerEphemeralDhModulus(unsafeSafePrime);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        DHEServerKeyExchangeMessage dheServerKeyExchange = new DHEServerKeyExchangeMessage();
        workflowTrace.addTlsAction(
                new SendAction(dheServerKeyExchange, new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
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
}
