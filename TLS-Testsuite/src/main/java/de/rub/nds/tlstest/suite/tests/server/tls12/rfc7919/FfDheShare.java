/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7919;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ExplicitModelingConstraints;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.ManualConfig;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

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

    @RFC(number = 7919, section = "4. Server Behavior and 5.1. Checking the Peer's Public Key")
    @AnvilTest(
            description =
                    "[...] the server MUST verify that 1 < dh_Yc < dh_p - 1. "
                            + "If dh_Yc is out of range, the server MUST terminate the connection "
                            + "with a fatal handshake_failure(40) alert. [...]"
                            + "Peers MUST validate each other's public key Y (dh_Ys offered by the "
                            + "server or dh_Yc offered by the client) by ensuring that 1 < Y < p-1.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
    @ManualConfig(identifiers = "FFDHE_SHARE_OUT_OF_BOUNDS")
    @HandshakeCategory(SeverityLevel.INFORMATIONAL)
    @ComplianceCategory(SeverityLevel.HIGH)
    @KeyExchange(supported = KeyExchangeType.DH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void shareOutOfBounds(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

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

    @AnvilTest(
            description =
                    "If a compatible TLS server receives a Supported Groups extension from "
                            + "a client that includes any FFDHE group (i.e., any codepoint between "
                            + "256 and 511, inclusive, even if unknown to the server), and if none "
                            + "of the client-proposed FFDHE groups are known and acceptable to the "
                            + "server, then the server MUST NOT select an FFDHE cipher suite.")
    @RFC(number = 7919, section = "4. Server Behavior")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @MethodCondition(method = "supportsDheCipherSuiteAndNamedGroups")
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void negotiatesNonFfdheIfNecessary(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
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

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertNotEquals(
                                    "Server negotiated DHE cipher suite",
                                    parameterCombination
                                            .getParameter(CipherSuiteDerivation.class)
                                            .getSelectedValue(),
                                    i.getState().getTlsContext().getSelectedCipherSuite());
                        });
    }

    @AnvilTest(
            description =
                    "If a compatible TLS server receives a Supported Groups extension from "
                            + "a client that includes any FFDHE group (i.e., any codepoint between "
                            + "256 and 511, inclusive, even if unknown to the server), and if none "
                            + "of the client-proposed FFDHE groups are known and acceptable to the "
                            + "server, then the server MUST NOT select an FFDHE cipher suite.[...]"
                            + "If the extension is present "
                            + "with FFDHE groups, none of the client's offered groups are acceptable "
                            + "by the server, and none of the client's proposed non-FFDHE cipher "
                            + "suites are acceptable to the server, the server MUST end the "
                            + "connection with a fatal TLS alert of type insufficient_security(71).")
    @RFC(number = 7919, section = "4. Server Behavior")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @ExcludeParameter("NAMED_GROUP")
    @MethodCondition(method = "supportsNamedFfdheGroups")
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void abortsWhenGroupsDontOverlap(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddEllipticCurveExtension(true);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        clientHello
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(getUnsupportedNamedGroup()));

        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(
                                    i, AlertDescription.INSUFFICIENT_SECURITY);
                        });
    }

    @AnvilTest(
            description =
                    "A compatible TLS server that receives the Supported Groups extension "
                            + "with FFDHE codepoints in it and that selects an FFDHE cipher suite "
                            + "MUST select one of the client's offered groups. [...]"
                            + "A TLS server MUST NOT select a named FFDHE group that was not offered "
                            + "by a compatible client.")
    @RFC(number = 7919, section = "4. Server Behavior")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getSupportedFfdheNamedGroups")
    @ManualConfig(identifiers = "NAMED_GROUP")
    @ExplicitModelingConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "getEmptyConstraintsList")
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void respectsOfferedGroups(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        NamedGroup ffdheGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        config.setDefaultClientNamedGroups(ffdheGroup);
        config.setAddEllipticCurveExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertEquals(
                                    "Server did not respect the offered group",
                                    ffdheGroup,
                                    i.getState().getTlsContext().getSelectedGroup());
                        });
    }

    @AnvilTest(
            description =
                    "A TLS server MUST NOT select an FFDHE cipher suite if the client did "
                            + "not offer one, even if the client offered an FFDHE group in the "
                            + "Supported Groups extension.")
    @RFC(number = 7919, section = "4. Server Behavior")
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void doesNotNegotiateDheCipherSuiteWhenNotOffered(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
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

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertFalse(
                                    "Server selected an FFDHE cipher suite",
                                    AlgorithmResolver.getKeyExchangeAlgorithm(
                                                    i.getState()
                                                            .getTlsContext()
                                                            .getSelectedCipherSuite())
                                            .isKeyExchangeDh());
                        });
    }

    public List<DerivationParameter<TlsAnvilConfig, NamedGroup>> getSupportedFfdheNamedGroups(
            AnvilTestTemplate scope) {
        List<DerivationParameter<TlsAnvilConfig, NamedGroup>> parameterValues = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getFfdheNamedGroups()
                .forEach(group -> parameterValues.add(new NamedGroupDerivation(group)));
        return parameterValues;
    }

    public List<ConditionalConstraint> getEmptyConstraintsList(AnvilTestTemplate scope) {
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
