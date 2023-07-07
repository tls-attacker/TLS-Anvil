/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7919;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExplicitModelingConstraints;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.LegacyConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@Tag("dheshare")
@RFC(number = 7919, section = "3. Client Behavior")
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

    @RFC(number = 7919, section = "3. Client Behavior and 5.1. Checking the Peer's Public Key")
    @AnvilTest(
            description =
                    "[...] the client MUST verify that dh_Ys is in the range 1 < "
                            + "dh_Ys < dh_p - 1.  If dh_Ys is not in this range, the client MUST "
                            + "terminate the connection with a fatal handshake_failure(40) alert. [...]"
                            + "Peers MUST validate each other's public key Y (dh_Ys offered by the "
                            + "server or dh_Yc offered by the client) by ensuring that 1 < Y < p-1.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ScopeExtensions(TlsParameterType.FFDHE_SHARE_OUT_OF_BOUNDS)
    @HandshakeCategory(SeverityLevel.INFORMATIONAL)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    public void shareOutOfBounds(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.addTlsActions(
                new SendAction(ActionOption.MAY_FAIL, new ServerHelloDoneMessage()),
                new ReceiveAction(new AlertMessage()));
        DHEServerKeyExchangeMessage SKE =
                (DHEServerKeyExchangeMessage)
                        WorkflowTraceUtil.getLastSendMessage(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        byte[] publicShare = c.getDefaultServerDhPublicKey().toByteArray();
        SKE.setPublicKey(publicShare);
        SKE.getPublicKey().setModification(new ByteArrayExplicitValueModification(publicShare));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            // accept both Illegal Parameter and Handshake Failure as RFC 8446 and
                            // 7919 demand different alerts
                            if (msg != null
                                    && !msg.getDescription()
                                            .getValue()
                                            .equals(
                                                    AlertDescription.ILLEGAL_PARAMETER
                                                            .getValue())) {
                                Validator.testAlertDescription(
                                        i, AlertDescription.HANDSHAKE_FAILURE, msg);
                            }
                        });
    }

    @Test
    @TestDescription(
            "If the client also supports and wants "
                    + "to offer ECDHE key exchange, it MUST use a single Supported Groups "
                    + "extension to include all supported groups (both ECDHE and FFDHE "
                    + "groups).")
    @RFC(number = 7919, section = "3. Client Behavior")
    @MethodCondition(method = "supportsFfdheAndEcNamedGroups")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void listsCurvesAndFfdheCorrectly() {
        // we always test for duplicate extensions anyway
        assertFalse(
                "Client offered EC Cipher Suites and FFDHE groups but no EC Named Groups",
                context.getFeatureExtractionResult().getNamedGroups().isEmpty());
    }

    @AnvilTest(
            description =
                    "A client that offers a group MUST be able and willing to perform a DH "
                            + "key exchange using that group.")
    @RFC(number = 7919, section = "3. Client Behavior")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getSupportedFfdheNamedGroups")
    @ManualConfig(TlsParameterType.NAMED_GROUP)
    @ExplicitModelingConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "getEmptyConstraintsList")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void supportsOfferedFfdheGroup(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        NamedGroup ffdheGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        config.setDefaultServerNamedGroups(ffdheGroup);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertEquals(
                                    "Invalid NamedGroup set in context",
                                    ffdheGroup,
                                    i.getState().getTlsContext().getSelectedGroup());
                        });
    }

    @AnvilTest(
            description =
                    "This document cannot enumerate all possible safe local policy (the "
                            + "safest may be to simply reject all custom groups), but compatible "
                            + "clients that accept some custom groups from the server MUST do at "
                            + "least cursory checks on group size and may take other properties into "
                            + "consideration as well. [...]"
                            + "A compatible client that accepts FFDHE cipher suites using custom "
                            + "groups from non-compatible servers MUST reject any group with |dh_p| "
                            + "< 768 bits")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ScopeLimitations(TlsParameterType.NAMED_GROUP)
    @Tag("new")
    public void performsRequiredSecurityCheck(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        // 767 bits "safe prime"
        BigInteger unsafeSafePrime =
                new BigInteger(
                        "7030affcfe478388a7b6e16019c66524d69e231c4b556d32d530f636f402be0afb0dbc8529e955c3b2254782bfec749c1e751a3d4bdbaa9505cb6f5cd7945e307c846f714ce98b805c6f90ef06fc58f853e316417df7f8189af7b9e9c3e5abb3",
                        16);
        BigInteger generator = new BigInteger("2", 16);

        config.setDefaultServerNamedGroups(new LinkedList<>());
        config.setDefaultServerDhGenerator(generator);
        config.setDefaultServerDhModulus(unsafeSafePrime);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        DHEServerKeyExchangeMessage dheServerKeyExchange = new DHEServerKeyExchangeMessage();
        workflowTrace.addTlsAction(
                new SendAction(dheServerKeyExchange, new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    public List<DerivationParameter<TlsAnvilConfig, NamedGroup>> getSupportedFfdheNamedGroups(
            DerivationScope scope) {
        List<DerivationParameter<TlsAnvilConfig, NamedGroup>> parameterValues = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getFfdheNamedGroups()
                .forEach(group -> parameterValues.add(new NamedGroupDerivation(group)));
        return parameterValues;
    }

    public List<LegacyConditionalConstraint> getEmptyConstraintsList(DerivationScope scope) {
        return new LinkedList<>();
    }
}
