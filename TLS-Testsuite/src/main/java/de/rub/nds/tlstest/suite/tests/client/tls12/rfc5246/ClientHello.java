/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import static org.junit.Assert.assertFalse;

import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class ClientHello extends Tls12Test {

    @Test
    @RFC(number = 5246, section = "7.4.1.2. Client Hello")
    @TestDescription("This vector MUST contain, and all implementations MUST support, CompressionMethod.null. "
            + "Thus, a client and server will always be able to agree on a compression method.")
    @Interoperability(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    @Handshake(SeverityLevel.MEDIUM)
    public void supportsNullcompressionMethod() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        byte[] compression = clientHelloMessage.getCompressions().getValue();
        boolean containsZero = false;
        boolean containsOther = false;
        for (byte i : compression) {
            if (i == 0) {
                containsZero = true;
            }
        }
        assertTrue("ClientHello does not contain compression method null", containsZero);
    }
    
    @Test
    @RFC(number = 7457, section = "2.6.  Compression Attacks: CRIME, TIME, and BREACH")
    @TestDescription("The CRIME attack (CVE-2012-4929) allows an active attacker to " +
            "decrypt ciphertext (specifically, cookies) when TLS is used with TLS- " +
            "level compression.")
    @Security(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    @Handshake(SeverityLevel.MEDIUM)
    public void offersNonNullCompressionMethod() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        byte[] compression = clientHelloMessage.getCompressions().getValue();
        boolean containsZero = false;
        boolean containsOther = false;
        for (byte i : compression) {
            if (i != 0) {
                containsOther = true;
                break;
            }
        }
        assertFalse("ClientHello contained compression method other than Null", containsOther);
    }
    
    public ConditionEvaluationResult sentSignatureAndHashAlgorithmsExtension() {
        return context.getReceivedClientHelloMessage().getExtension(SignatureAndHashAlgorithmsExtensionMessage.class) == null
                ? ConditionEvaluationResult.disabled("Target did not sent SignatureAndHashAlgorithms Extension") : ConditionEvaluationResult.enabled("");
    }
    
    @Test
    @Interoperability(SeverityLevel.CRITICAL)
    @TestDescription("The client uses the \"signature_algorithms\" extension to indicate to " +
            "the server which signature/hash algorithm pairs may be used in " +
            "digital signatures.")
    @MethodCondition(method = "sentSignatureAndHashAlgorithmsExtension")
    public void offeredSignatureAlgorithmsForAllCipherSuites() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        List<CipherSuite> proposedCipherSuites = CipherSuite.getCipherSuites(clientHelloMessage.getCipherSuites().getValue());
        proposedCipherSuites = proposedCipherSuites.stream().filter(cipherSuite -> !cipherSuite.isTLS13() && cipherSuite.isRealCipherSuite()).collect(Collectors.toList());
        List<CipherSuite> coveredCipherSuites = new LinkedList<>();
        for(CipherSuite cipherSuite : proposedCipherSuites) {
            boolean foundMatch = false;
            switch(AlgorithmResolver.getCertificateKeyType(cipherSuite)) {
                case DH:
                case DSS:
                    if(providedSignatureAlgorithm(SignatureAlgorithm.DSA)) {
                       foundMatch = true; 
                    }
                    break;
                case ECDH:
                case ECDSA:
                case ECNRA:
                    if(providedSignatureAlgorithm(SignatureAlgorithm.ECDSA)
                            || providedSignatureAlgorithm(SignatureAlgorithm.ED25519) 
                            || providedSignatureAlgorithm(SignatureAlgorithm.ED448)) {
                       foundMatch = true; 
                    }
                    break;
                case RSA:
                    if(providedSignatureAlgorithm(SignatureAlgorithm.RSA)
                            || providedSignatureAlgorithm(SignatureAlgorithm.RSA_PSS_PSS) 
                            || providedSignatureAlgorithm(SignatureAlgorithm.RSA_PSS_RSAE)) {
                       foundMatch = true; 
                    }
                    break;
                case GOST01:
                    if(providedSignatureAlgorithm(SignatureAlgorithm.GOSTR34102001)) {
                       foundMatch = true; 
                    }
                    break;
                case GOST12:
                    if(providedSignatureAlgorithm(SignatureAlgorithm.GOSTR34102012_256) 
                            || providedSignatureAlgorithm(SignatureAlgorithm.GOSTR34102012_512)) {
                       foundMatch = true; 
                    }
                    break;  
            }
            if(foundMatch) {
                coveredCipherSuites.add(cipherSuite);
            }
        }
        proposedCipherSuites.removeAll(coveredCipherSuites);
        assertTrue("Client did not provide a SignatureAlgorithm for all cipher suites " +
                        proposedCipherSuites.parallelStream().map(Enum::name).collect(Collectors.joining(",")),proposedCipherSuites.isEmpty());
    }
        
    private boolean providedSignatureAlgorithm(SignatureAlgorithm requiredAlgorithm) {
        SignatureAndHashAlgorithmsExtensionMessage sigHashExtension = context.getReceivedClientHelloMessage().getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        List<SignatureAndHashAlgorithm> algorithmPairs = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(sigHashExtension.getSignatureAndHashAlgorithms().getValue());
        return algorithmPairs.stream().anyMatch(algoirthmPair -> algoirthmPair.getSignatureAlgorithm() == requiredAlgorithm);
    }
}
