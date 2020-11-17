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

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.Set;

import static org.junit.Assert.*;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;


@RFC(number = 8422, section = "4. TLS Extensions for ECC")
@ClientTest
public class TLSExtensionForECC extends Tls12Test {

    @Test
    @KeyExchange(supported = {KeyExchangeType.DH, KeyExchangeType.RSA})
    @TestDescription("The client MUST NOT include these extensions in the ClientHello " +
            "message if it does not propose any ECC cipher suites.")
    public void bothECExtensions_WithoutECCCipher() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);
        Set<CipherSuite> suites = context.getSiteReport().getCipherSuites();
        suites.removeIf(cs -> !KeyExchangeType.ECDH.compatibleWithCiphersuite(cs));

        if (suites.size() == 0) {
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
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @Security(SeverityLevel.LOW)
    @TestDescription("Deprecated groups should not be offered by a client")
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

}
