/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8422;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.*;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Tag;

@ServerTest
public class TLSExtensionForECC extends Tls12Test {

    private static final Logger LOGGER = LogManager.getLogger();

    @AnvilTest(id = "8422-rxF7z2tc5t")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void addUnknownEllipticCurve(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        ((ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO))
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.insert(new byte[] {(byte) 123, 124}, 0));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8422-Dk77D7HNBW")
    @ExcludeParameter("NAMED_GROUP")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void onlyInvalidEllipticCurve(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new SendAction(chm), new ReceiveAction(new AlertMessage()));

        chm.getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(new byte[] {(byte) 123, 124}));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    @AnvilTest(id = "8422-4G8mbkQ9LM")
    @ExcludeParameter("NAMED_GROUP")
    @ManualConfig(identifiers = "CIPHER_SUITE")
    @KeyExchange(supported = {KeyExchangeType.RSA, KeyExchangeType.DH})
    public void invalidEllipticCurve_WithNonECCCiphersuite(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        List<CipherSuite> cipherSuiteList =
                CipherSuite.getImplemented().stream()
                        .filter(i -> KeyExchangeType.forCipherSuite(i) == KeyExchangeType.ECDH)
                        .collect(Collectors.toList());
        cipherSuiteList.add(
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue());

        c.setDefaultClientSupportedCipherSuites(cipherSuiteList);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm), new ReceiveTillAction(new ServerHelloDoneMessage()));

        chm.getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(new byte[] {(byte) 123, 124}));

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        WorkflowTrace trace = state.getWorkflowTrace();
        ServerHelloMessage message = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(message, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        assertArrayEquals(
                parameterCombination
                        .getParameter(CipherSuiteDerivation.class)
                        .getSelectedValue()
                        .getByteValue(),
                message.getSelectedCipherSuite().getValue(),
                AssertMsgs.UNEXPECTED_CIPHER_SUITE);
    }

    /*@AnvilTest for use in TLS.  Only three have\n" +
    "seen much use.  This specification is deprecating the rest (with\n" +
    "numbers 1-22).  This specification also deprecates the explicit " +
    "curves with identifiers 0xFF01 and 0xFF02.  It also adds the new\n" +
    "curves defined in [RFC7748]", securitySeverity = SeverityLevel.LOW)*/
    @NonCombinatorialAnvilTest(id = "8422-ErkUw4SDEy")
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    public void supportsDeprecated() {
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
                "Deprecated group(s) supported: "
                        + deprecatedFound.stream()
                                .map(NamedGroup::name)
                                .collect(Collectors.joining(",")));
    }

    @AnvilTest(id = "8422-PtimgKWxss")
    @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void manyGroupsOffered(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        // add 52 additional groups to reach 53, which is the sum of all
        // named groups, explicit curves, and grease values
        byte[] allExplicitGroups = new byte[53 * 2];
        for (int i = 0; i < (52 * 2); i = i + 2) {
            allExplicitGroups[i] = (byte) 0x0A;
            allExplicitGroups[i + 1] = (byte) i;
        }
        allExplicitGroups[104] = selectedGroup.getValue()[0];
        allExplicitGroups[105] = selectedGroup.getValue()[1];
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        clientHello
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(allExplicitGroups));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8422-4MTo5xU82i")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ECDH},
            requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isInvalidCurveApplicableNamedGroup")
    @Tag("new")
    public void rejectsInvalidCurvePoints(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        EllipticCurve curve = (EllipticCurve) selectedGroup.getGroupParameters().getGroup();
        InvalidCurvePoint invalidCurvePoint = InvalidCurvePoint.largeOrder(selectedGroup);
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

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        ECDHClientKeyExchangeMessage clientKeyExchangeMessage =
                (ECDHClientKeyExchangeMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        clientKeyExchangeMessage.setPublicKey(Modifiable.explicit(serializedPoint));

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8422-fV4R6XHPeJ")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isXCurve")
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
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

        byte[] serializedPublicKey = curve.encodeCoordinate(invalidPoint.getFieldX().getData());
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        ECDHClientKeyExchangeMessage clientKeyExchangeMessage =
                (ECDHClientKeyExchangeMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        clientKeyExchangeMessage.setPublicKey(Modifiable.explicit(serializedPublicKey));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    @AnvilTest(id = "8422-ymcrNp3RQw")
    @DynamicValueConstraints(
            affectedIdentifiers = "CIPHER_SUITE",
            methods = "isEcdheAnonCipherSuite")
    @Tag("new")
    public void leavesPublicKeyUnsignedInAnon(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        ECDHEServerKeyExchangeMessage serverKeyExchange =
                workflowTrace.getFirstReceivedMessage(ECDHEServerKeyExchangeMessage.class);
        assertEquals(
                (long) 0,
                (long) serverKeyExchange.getSignatureLength().getValue(),
                "Server provided a non-empty signature field in Server Key Exchange message");
    }

    public boolean isEcdheAnonCipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isAnon()
                && cipherSuite.isEphemeral()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isEC();
    }

    public boolean isXCurve(NamedGroup group) {
        return group != null && group.name().contains("ECDH_X");
    }

    public boolean isInvalidCurveApplicableNamedGroup(NamedGroup group) {
        if (group != null
                && group.isCurve()
                && !group.isGost()
                && !(group.getGroupParameters().getGroup() instanceof RFC7748Curve)) {
            return true;
        }
        return false;
    }
}
