/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8422;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlstest.framework.Validator;

import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class TLSExtensionForECC extends Tls12Test {

    private static final Logger LOGGER = LogManager.getLogger();

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @AnvilTest(
            description =
                    "A server that receives a ClientHello containing one or both of these "
                            + "extensions MUST use the client's enumerated capabilities to guide its "
                            + "selection of an appropriate cipher suite.  One of the proposed ECC "
                            + "cipher suites must be negotiated only if the server can successfully "
                            + "complete the handshake while using the curves and point formats "
                            + "supported by the client (cf. Sections 5.3 and 5.4).")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @InteroperabilityCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void addUnknownEllipticCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace
                .getFirstSendMessage(ClientHelloMessage.class)
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.insert(new byte[] {(byte) 123, 124}, 0));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @AnvilTest(
            description =
                    "If a server does not understand the Supported Elliptic Curves Extension, "
                            + "does not understand the Supported Point Formats Extension, or is unable to complete the ECC handshake "
                            + "while restricting itself to the enumerated curves and point formats, "
                            + "it MUST NOT negotiate the use of an ECC cipher suite.")
    @ScopeLimitations(TlsParameterType.NAMED_GROUP)
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void onlyInvalidEllipticCurve(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new SendAction(chm), new ReceiveAction(new AlertMessage()));

        chm.getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(new byte[] {(byte) 123, 124}));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @RFC(number = 8422, section = "4. TLS Extensions for ECC and 5.1. Client Hello Extensions")
    @AnvilTest(
            description =
                    "Servers implementing ECC "
                            + "cipher suites MUST support these extensions, and when a client uses "
                            + "these extensions, servers MUST NOT negotiate the use of an ECC cipher "
                            + "suite unless they can complete the handshake while respecting the "
                            + "choice of curves specified by the client. [...]"
                            + "If a server does not understand the Supported Elliptic Curves Extension, "
                            + "does not understand the Supported Point Formats Extension, or is unable to complete the ECC handshake "
                            + "while restricting itself to the enumerated curves and point formats, "
                            + "it MUST NOT negotiate the use of an ECC cipher suite.")
    @ScopeLimitations(TlsParameterType.NAMED_GROUP)
    @ManualConfig(TlsParameterType.CIPHER_SUITE)
    @KeyExchange(supported = {KeyExchangeType.RSA, KeyExchangeType.DH})
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void invalidEllipticCurve_WithNonECCCiphersuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        List<CipherSuite> cipherSuiteList =
                CipherSuite.getImplemented().stream()
                        .filter(i -> KeyExchangeType.forCipherSuite(i) == KeyExchangeType.ECDH)
                        .collect(Collectors.toList());
        cipherSuiteList.add(
                derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue());

        c.setDefaultClientSupportedCipherSuites(cipherSuiteList);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm), new ReceiveTillAction(new ServerHelloDoneMessage()));

        chm.getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(new byte[] {(byte) 123, 124}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);

                            WorkflowTrace trace = i.getWorkflowTrace();
                            ServerHelloMessage message =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            assertNotNull(AssertMsgs.ServerHelloNotReceived, message);
                            assertArrayEquals(
                                    AssertMsgs.UnexpectedCipherSuite,
                                    derivationContainer
                                            .getDerivation(CipherSuiteDerivation.class)
                                            .getSelectedValue()
                                            .getByteValue(),
                                    message.getSelectedCipherSuite().getValue());
                        });
    }

    @RFC(number = 8422, section = "5.1.1 Supported Elliptic Curves Extension")
    /*@AnvilTest(description = " RFC 4492 defined 25 different curves in the NamedCurve registry (now\n" +
    "renamed the \"TLS Supported Groups\" registry, although the enumeration\n" +
    "below is still named NamedCurve) for use in TLS.  Only three have\n" +
    "seen much use.  This specification is deprecating the rest (with\n" +
    "numbers 1-22).  This specification also deprecates the explicit " +
    "curves with identifiers 0xFF01 and 0xFF02.  It also adds the new\n" +
    "curves defined in [RFC7748]", securitySeverity = SeverityLevel.LOW)*/
    @Test
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @TestDescription("Deprecated groups should not be supported")
    @CryptoCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.LOW)
    @DeprecatedFeatureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void supportsDeprecated(WorkflowRunner runner) {
        List<NamedGroup> deprecatedFound = new LinkedList<>();
        for (NamedGroup group : context.getFeatureExtractionResult().getNamedGroups()) {
            if (group.getIntValue() < NamedGroup.SECP256R1.getIntValue()
                    || group == NamedGroup.EXPLICIT_CHAR2
                    || group == NamedGroup.EXPLICIT_PRIME) {
                deprecatedFound.add(group);
            }
        }
        assertTrue(
                "Deprecated group(s) supported: "
                        + deprecatedFound.stream()
                                .map(NamedGroup::name)
                                .collect(Collectors.joining(",")),
                deprecatedFound.isEmpty());
    }

    @AnvilTest(description = "NamedCurve named_curve_list<2..2^16-1>")
    @RFC(number = 8422, section = "5.1.1.  Supported Elliptic Curves Extension")
    @ScopeLimitations(TlsParameterType.INCLUDE_GREASE_NAMED_GROUPS)
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void manyGroupsOffered(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
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
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        clientHello
                .getExtension(EllipticCurvesExtensionMessage.class)
                .setSupportedGroups(Modifiable.explicit(allExplicitGroups));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(
            description =
                    "With the NIST curves, each party MUST validate the public key sent by "
                            + "its peer in the ClientKeyExchange and ServerKeyExchange messages.  A "
                            + "receiving party MUST check that the x and y parameters from the "
                            + "peer's public value satisfy the curve equation, y^2 = x^3 + ax + b "
                            + "mod p.")
    @RFC(number = 8422, section = "5.11. Public Key Validation")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ECDH},
            requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isInvalidCurveApplicableNamedGroup")
    @CryptoCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @Tag("new")
    public void rejectsInvalidCurvePoints(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        EllipticCurve curve = CurveFactory.getCurve(selectedGroup);
        InvalidCurvePoint invalidCurvePoint = InvalidCurvePoint.largeOrder(selectedGroup);
        Point serializablePoint =
                new Point(
                        new FieldElementFp(
                                invalidCurvePoint.getPublicPointBaseX(), curve.getModulus()),
                        new FieldElementFp(
                                invalidCurvePoint.getPublicPointBaseY(), curve.getModulus()));
        byte[] serializedPoint =
                PointFormatter.formatToByteArray(
                        selectedGroup, serializablePoint, ECPointFormat.UNCOMPRESSED);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        ECDHClientKeyExchangeMessage clientKeyExchangeMessage =
                (ECDHClientKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        clientKeyExchangeMessage.setPublicKey(Modifiable.explicit(serializedPoint));

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(
            description =
                    "if either party obtains all-zeroes x_S, it MUST "
                            + "abort the handshake (as required by definition of X25519 and X448). [...]"
                            + "With X25519 and X448, a receiving party MUST check whether the "
                            + "computed premaster secret is the all-zero value and abort the "
                            + "handshake if so")
    @RFC(
            number = 8422,
            section = "5.10. ECDH, ECDSA, and RSA Computations and 5.11. Public Key Validation")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isXCurve")
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        TwistedCurvePoint groupSpecificPoint = TwistedCurvePoint.smallOrder(selectedGroup);
        RFC7748Curve curve = (RFC7748Curve) CurveFactory.getCurve(selectedGroup);
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
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        clientKeyExchangeMessage.setPublicKey(Modifiable.explicit(serializedPublicKey));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(
            description =
                    "The server MUST send an ephemeral ECDH public key and a specification "
                            + "of the corresponding curve in the ServerKeyExchange message.  These "
                            + "parameters MUST NOT be signed.")
    @RFC(number = 8422, section = "2.3.  ECDH_anon")
    @DynamicValueConstraints(
            affectedIdentifiers = "CIPHER_SUITE",
            methods = "isEcdheAnonCipherSuite")
    @HandshakeCategory(SeverityLevel.LOW)
    @InteroperabilityCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void leavesPublicKeyUnsignedInAnon(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            ECDHEServerKeyExchangeMessage serverKeyExchange =
                                    workflowTrace.getFirstReceivedMessage(
                                            ECDHEServerKeyExchangeMessage.class);
                            assertEquals(
                                    "Server provided a non-empty signature field in Server Key Exchange message",
                                    (long) 0,
                                    (long) serverKeyExchange.getSignatureLength().getValue());
                        });
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
                && !(CurveFactory.getCurve(group) instanceof RFC7748Curve)) {
            return true;
        }
        return false;
    }
}
