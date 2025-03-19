/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc8422;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.*;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class TLSExtensionForECC extends Tls12Test {

    public ConditionEvaluationResult doesNotOfferEccCipherSuite() {
        if (context.getFeatureExtractionResult().getCipherSuites() == null
                || context.getFeatureExtractionResult().getCipherSuites().stream()
                        .anyMatch(
                                cipherSuite -> {
                                    return AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                                            .isEC();
                                })) {
            return ConditionEvaluationResult.disabled("Client supports ECC cipher suite");
        }
        return ConditionEvaluationResult.enabled("");
    }

    @NonCombinatorialAnvilTest(id = "8422-exVPmQoGGM")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @Tag("adjusted")
    public void invalidPointFormat() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(msg, AssertMsgs.CLIENT_HELLO_NOT_RECEIVED);
        ECPointFormatExtensionMessage poinfmtExt =
                msg.getExtension(ECPointFormatExtensionMessage.class);

        boolean rfc8422curves = false;
        boolean nonRfc8422curve = false;
        for (NamedGroup group : context.getFeatureExtractionResult().getNamedGroups()) {
            if (isRfc8422Curve(group)) {
                rfc8422curves = true;
            } else {
                nonRfc8422curve = true;
            }
        }

        if (poinfmtExt != null) {
            boolean contains_zero = false;
            boolean contains_other = false;
            for (byte b : poinfmtExt.getPointFormats().getValue()) {
                if (b == ECPointFormat.UNCOMPRESSED.getValue()) {
                    contains_zero = true;
                } else {
                    contains_other = true;
                }
            }
            assertTrue(
                    contains_zero, "ECPointFormatExtension does not contain uncompressed format");
            if (rfc8422curves && !nonRfc8422curve) {
                assertFalse(
                        contains_other,
                        "ECPointFormatExtension contains compressed or invalid format");
            }
        }
    }

    @NonCombinatorialAnvilTest(id = "8422-zPzy3N3kzG")
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    public void offeredDeprecatedGroup() {
        boolean deprecated = false;
        List<NamedGroup> deprecatedFound = new LinkedList<>();
        int secp256r1IntVal = ArrayConverter.bytesToInt(NamedGroup.SECP256R1.getValue());
        for (NamedGroup group : context.getFeatureExtractionResult().getNamedGroups()) {
            int groupIntVal = ArrayConverter.bytesToInt(group.getValue());
            if (groupIntVal < secp256r1IntVal
                    || group == NamedGroup.EXPLICIT_CHAR2
                    || group == NamedGroup.EXPLICIT_PRIME) {
                deprecatedFound.add(group);
            }
        }
        assertTrue(
                deprecatedFound.isEmpty(),
                "Found deprecated group: "
                        + deprecatedFound.stream()
                                .map(NamedGroup::name)
                                .collect(Collectors.joining(",")));
    }

    private boolean isRfc8422Curve(NamedGroup group) {
        if (group == NamedGroup.SECP256R1
                || group == NamedGroup.SECP384R1
                || group == NamedGroup.SECP521R1
                || group == NamedGroup.ECDH_X25519
                || group == NamedGroup.ECDH_X448) {
            return true;
        }
        return false;
    }

    public boolean isSecpCurve(NamedGroup group) {
        if (group != null
                && group.isEcGroup()
                && !group.isGost()
                && !(((NamedEllipticCurveParameters) group.getGroupParameters()).getGroup()
                        instanceof RFC7748Curve)) {
            return true;
        }
        return false;
    }

    @AnvilTest(id = "8422-A5SiH3AcVB")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ECDH},
            requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isSecpCurve")
    public void rejectsInvalidCurvePoints(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        EllipticCurve curve = (EllipticCurve) selectedGroup.getGroupParameters().getGroup();
        InvalidCurvePoint invalidCurvePoint = InvalidCurvePoint.smallOrder(selectedGroup);
        Point serializablePoint =
                new Point(
                        new FieldElementFp(
                                invalidCurvePoint.getPublicPointBaseX(), curve.getModulus()),
                        new FieldElementFp(
                                invalidCurvePoint.getPublicPointBaseY(), curve.getModulus()));
        byte[] serializedPoint =
                PointFormatter.formatToByteArray(
                        selectedGroup.getGroupParameters(),
                        serializablePoint,
                        PointFormat.UNCOMPRESSED);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ECDHEServerKeyExchangeMessage serverKeyExchangeMessage =
                (ECDHEServerKeyExchangeMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        serverKeyExchangeMessage.setPublicKey(Modifiable.explicit(serializedPoint));

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8422-nGxjfcCt1i")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ECDH},
            requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isXCurve")
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        TwistedCurvePoint groupSpecificPoint = TwistedCurvePoint.smallOrder(selectedGroup);
        RFC7748Curve curve = (RFC7748Curve) selectedGroup.getGroupParameters().getGroup();
        Point invalidPoint =
                new Point(
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseX(), curve.getModulus()),
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseY(), curve.getModulus()));

        ECDHEServerKeyExchangeMessage serverKeyExchange = new ECDHEServerKeyExchangeMessage();
        byte[] serializedPublicKey = curve.encodeCoordinate(invalidPoint.getFieldX().getData());
        serverKeyExchange.setPublicKey(Modifiable.explicit(serializedPublicKey));
        workflowTrace.addTlsAction(new SendAction(serverKeyExchange));
        workflowTrace.addTlsAction(
                new SendAction(ActionOption.MAY_FAIL, new ServerHelloDoneMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8422-DknikJ9VC5")
    @ModelFromScope(modelType = "CERTIFICATE")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isSecpCurve")
    @KeyExchange(
            supported = {KeyExchangeType.ECDH},
            requiresServerKeyExchMsg = true)
    @Tag("new")
    public void respectsPointFormat(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setDefaultServerSupportedPointFormats(ECPointFormat.UNCOMPRESSED);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        ECDHClientKeyExchangeMessage clientKeyExchange =
                state.getWorkflowTrace()
                        .getFirstReceivedMessage(ECDHClientKeyExchangeMessage.class);
        assertEquals(
                0x04,
                clientKeyExchange.getPublicKey().getValue()[0],
                "Client did not respect our Point Format");
    }

    @NonCombinatorialAnvilTest(id = "8422-jJBYYpiKBH")
    @MethodCondition(method = "doesNotOfferEccCipherSuite")
    @Tag("new")
    public void offersExtensionsWithoutCipher() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        assertFalse(
                clientHello.containsExtension(ExtensionType.EC_POINT_FORMATS),
                "Client offered EC Point Formats without an ECC Cipher Suite");
        // testing for Elliptic Curves Extension is not sensible as the extension
        // is now called Named Groups Extension and also negotiates FFDHE groups
    }

    public boolean isXCurve(NamedGroup group) {
        return group != null && group.name().contains("ECDH_X");
    }
}
