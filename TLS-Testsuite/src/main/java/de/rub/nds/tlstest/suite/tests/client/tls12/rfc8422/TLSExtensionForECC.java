/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc8422;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.attacks.ec.InvalidCurvePoint;
import de.rub.nds.tlsattacker.attacks.ec.TwistedCurvePoint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;


@RFC(number = 8422, section = "4. TLS Extensions for ECC")
@ClientTest
public class TLSExtensionForECC extends Tls12Test {

    public ConditionEvaluationResult doesNotOfferEccCipherSuite() {
        if (context.getSiteReport().getCipherSuites() == null || context.getSiteReport().getCipherSuites().stream().anyMatch(cipherSuite -> {return AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isEC();})) {
            return ConditionEvaluationResult.disabled("Client supports ECC cipher suite");
            
        }
        return ConditionEvaluationResult.enabled("");
    }
    
    @Test
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @TestDescription("A client compliant with this specification that supports no other " +
            "curves MUST send the following octets; note that the first two octets" +
            "indicate the extension type (Supported Point Formats Extension)[...]" +
            "If the Supported Point Formats " +
            "Extension is indeed sent, it MUST contain the value 0 (uncompressed) " +
            "as one of the items in the list of point formats. [...]" +
            "Implementations of this document MUST support the " +
            "uncompressed format for all of their supported curves and MUST NOT " +
            "support other formats for curves defined in this specification.  For " +
            "backwards compatibility purposes, the point format list extension MAY " +
            "still be included and contain exactly one value: the uncompressed " +
            "point format (0).")
    @RFC(number = 8422, section = "4. TLS Extensions for ECC, 5.1. Client Hello Extensions, and 5.1.2. Supported Point Formats Extension")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.MEDIUM)
    @Tag("adjusted")
    public void invalidPointFormat() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);
        ECPointFormatExtensionMessage poinfmtExt = msg.getExtension(ECPointFormatExtensionMessage.class);
        
        boolean rfc8422curves = false;
        boolean nonRfc8422curve = false;
        for(NamedGroup group: context.getSiteReport().getSupportedNamedGroups()) {
            if(isRfc8422Curve(group)) {
                rfc8422curves = true;
            } else {
                nonRfc8422curve = true;
            }
        }
        
        if(poinfmtExt != null) {
            boolean contains_zero = false;
            boolean contains_other = false;
            for (byte b : poinfmtExt.getPointFormats().getValue()) {
                if (b == ECPointFormat.UNCOMPRESSED.getValue()) {
                    contains_zero = true;
                } else {
                    contains_other = true;
                }
            }
            assertTrue("ECPointFormatExtension does not contain uncompressed format", contains_zero);
            if(rfc8422curves && !nonRfc8422curve) {
                assertFalse("ECPointFormatExtension contains compressed or invalid format", contains_other);
            }
        }
    }
    
    @Test
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @TestDescription("RFC 4492 defined 25 different curves in the NamedCurve registry (now "  +
        "renamed the \"TLS Supported Groups\" registry, although the enumeration " +
        "below is still named NamedCurve) for use in TLS. Only three have " +
        "seen much use. This specification is deprecating the rest (with " +
        "numbers 1-22).")
    @CryptoCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void offeredDeprecatedGroup() {
        boolean deprecated = false;
        List<NamedGroup> deprecatedFound = new LinkedList<>();
        for(NamedGroup group : context.getSiteReport().getSupportedNamedGroups()) {
            if(group.getIntValue() < NamedGroup.SECP256R1.getIntValue() || group == NamedGroup.EXPLICIT_CHAR2 || group == NamedGroup.EXPLICIT_PRIME) {
                deprecatedFound.add(group);
            }
        }
        assertTrue("Found deprecated group: " + deprecatedFound.stream().map(NamedGroup::name).collect(Collectors.joining(",")), deprecatedFound.isEmpty());
    }
    
    private boolean isRfc8422Curve(NamedGroup group) {
        if(group == NamedGroup.SECP256R1 
                || group == NamedGroup.SECP384R1
                || group == NamedGroup.SECP521R1
                || group == NamedGroup.ECDH_X25519
                || group == NamedGroup.ECDH_X448) {
            return true;
        }
        return false;
    }
    
    public boolean isSecpCurve(NamedGroup group) {
        if(group != null && group.isCurve() && !group.isGost() && !(CurveFactory.getCurve(group) instanceof RFC7748Curve)) {
            return true;
        }
        return false;
    }
    
    @TlsTest(description = "With the NIST curves, each party MUST validate the public key sent by " +
        "its peer in the ClientKeyExchange and ServerKeyExchange messages.  A " +
        "receiving party MUST check that the x and y parameters from the " +
        "peer's public value satisfy the curve equation, y^2 = x^3 + ax + b " +
        "mod p.")
    @RFC(number = 8422, section = "5.11. Public Key Validation")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isSecpCurve")
    @CryptoCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void rejectsInvalidCurvePoints(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        EllipticCurve curve = CurveFactory.getCurve(selectedGroup);
        InvalidCurvePoint invalidCurvePoint = InvalidCurvePoint.smallOrder(selectedGroup);
        Point serializablePoint =
            new Point(new FieldElementFp(invalidCurvePoint.getPublicPointBaseX(), curve.getModulus()), new FieldElementFp(
                invalidCurvePoint.getPublicPointBaseY(), curve.getModulus()));
        byte[] serializedPoint = PointFormatter.formatToByteArray(selectedGroup, serializablePoint, ECPointFormat.UNCOMPRESSED);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ECDHEServerKeyExchangeMessage serverKeyExchangeMessage = (ECDHEServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchangeMessage.setPublicKey(Modifiable.explicit(serializedPoint));
        
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "if either party obtains all-zeroes x_S, it MUST " +
        "abort the handshake (as required by definition of X25519 and X448). [...]" +
        "With X25519 and X448, a receiving party MUST check whether the " +
        "computed premaster secret is the all-zero value and abort the " +
        "handshake if so, as described in Section 6 of [RFC7748]")
    @RFC(number = 8446, section = "5.10. ECDH, ECDSA, and RSA Computations and 5.11. Public Key Validation")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isXCurve")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        
        TwistedCurvePoint groupSpecificPoint = TwistedCurvePoint.smallOrder(selectedGroup);
        RFC7748Curve curve = (RFC7748Curve) CurveFactory.getCurve(selectedGroup);
        Point invalidPoint = new Point(new FieldElementFp(groupSpecificPoint.getPublicPointBaseX(), curve.getModulus()),
                new FieldElementFp(groupSpecificPoint.getPublicPointBaseY(), curve.getModulus()));

        ECDHEServerKeyExchangeMessage serverKeyExchange = new ECDHEServerKeyExchangeMessage(config);
        byte[] serializedPublicKey = curve.encodeCoordinate(invalidPoint.getFieldX().getData());
        serverKeyExchange.setPublicKey(Modifiable.explicit(serializedPublicKey));
        workflowTrace.addTlsAction(new SendAction(serverKeyExchange));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "A client that receives a ServerHello message containing a Supported " +
        "Point Formats Extension MUST respect the server's choice of point " +
        "formats during the handshake (cf.  Sections 5.6 and 5.7).")
    @RFC(number = 8422, section = "5.2. Server Hello Extension")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isSecpCurve")
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void respectsPointFormat(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setDefaultServerSupportedPointFormats(ECPointFormat.UNCOMPRESSED);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            ECDHClientKeyExchangeMessage clientKeyExchange = i.getWorkflowTrace().getFirstReceivedMessage(ECDHClientKeyExchangeMessage.class);
            assertEquals("Client did not respect our Point Format" , 0x04, clientKeyExchange.getPublicKey().getValue()[0]);
        });
    }
    
    @Test
    @TestDescription("The client MUST NOT include these extensions in the ClientHello " +
        "message if it does not propose any ECC cipher suites.")
    @MethodCondition(method = "doesNotOfferEccCipherSuite")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void offersExtensionsWithoutCipher() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        assertFalse("Client offered EC Point Formats without an ECC Cipher Suite", clientHello.containsExtension(ExtensionType.EC_POINT_FORMATS));
        //testing for Elliptic Curves Extension is not sensible as the extension
        //is now called Named Groups Extension and also negotiates FFDHE groups
    }
    
    public boolean isXCurve(NamedGroup group) {
        return group != null && group.name().contains("ECDH_X");
    }
}
