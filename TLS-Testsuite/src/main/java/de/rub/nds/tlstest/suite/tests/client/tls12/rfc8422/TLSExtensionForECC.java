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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.Set;

import static org.junit.Assert.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;


@RFC(number = 8422, section = "4. TLS Extensions for ECC")
@ClientTest
public class TLSExtensionForECC extends Tls12Test {

    @Test
    @KeyExchange(supported = {KeyExchangeType.DH, KeyExchangeType.RSA})
    @TestDescription("The client MUST NOT include these extensions in the ClientHello " +
            "message if it does not propose any ECC cipher suites.")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    public void bothECExtensions_WithoutECCCipher() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);
        Set<CipherSuite> suites = context.getSiteReport().getCipherSuites();
        suites.removeIf(cs -> !KeyExchangeType.ECDH.compatibleWithCiphersuite(cs));

        if (suites.isEmpty()) {
            ECPointFormatExtensionMessage poinfmtExt = msg.getExtension(ECPointFormatExtensionMessage.class);
            EllipticCurvesExtensionMessage ecExt = msg.getExtension(EllipticCurvesExtensionMessage.class);
            assertNull("ECPointFormatExtension should be null", poinfmtExt);
            assertNull("EllipticCurveExtension should be null", ecExt);
        }
    }


    @Test
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @TestDescription("Implementations of this document MUST support the" +
            "uncompressed format for all of their supported curves and MUST NOT" +
            "support other formats for curves defined in this specification.  For" +
            "backwards compatibility purposes, the point format list extension MAY" +
            "still be included and contain exactly one value: the uncompressed" +
            "point format (0).")
    @Interoperability(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    public void invalidPointFormat() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);
        ECPointFormatExtensionMessage poinfmtExt = msg.getExtension(ECPointFormatExtensionMessage.class);
        
        boolean rfc8422curves = false;
        for(NamedGroup group: context.getSiteReport().getSupportedNamedGroups()) {
            if(isRfc8422Curve(group)) {
                rfc8422curves = true;
                break;
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
            if(rfc8422curves) {
                assertFalse("ECPointFormatExtension contains compressed or invalid format", contains_other);
            }
        }
    }
    
    /*@TlsTest(description = " RFC 4492 defined 25 different curves in the NamedCurve registry (now\n" +
            "renamed the \"TLS Supported Groups\" registry, although the enumeration\n" +
            "below is still named NamedCurve) for use in TLS.  Only three have\n" +
            "seen much use.  This specification is deprecating the rest (with\n" +
            "numbers 1-22).  This specification also deprecates the explicit " +
            "curves with identifiers 0xFF01 and 0xFF02.  It also adds the new\n" +
            "curves defined in [RFC7748]", securitySeverity = SeverityLevel.LOW)*/
    @Test
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @TestDescription("Deprecated groups should not be offered by a client")
    @Crypto(SeverityLevel.MEDIUM)
    @Security(SeverityLevel.MEDIUM)
    @DeprecatedFeature(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void offeredDeprecatedGroup() {
        boolean deprecated = false;
        for(NamedGroup group : context.getSiteReport().getSupportedNamedGroups()) {
            if(group.getIntValue() < NamedGroup.SECP256R1.getIntValue() || group == NamedGroup.EXPLICIT_CHAR2 || group == NamedGroup.EXPLICIT_PRIME) {
                deprecated = true;
                break;
            }
        }
        assertFalse("A deprecated group was offered", deprecated);
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
    
    public boolean isInvalidCurveApplicableNamedGroup(NamedGroup group) {
        if(group != null && group.isCurve() && !group.isGost() && !(CurveFactory.getCurve(group) instanceof RFC7748Curve)) {
            return true;
        }
        return false;
    }
    
    @TlsTest(description = "A lack of point validation might enable Invalid Curve Attacks")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isInvalidCurveApplicableNamedGroup")
    @Crypto(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.HIGH)
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
}
