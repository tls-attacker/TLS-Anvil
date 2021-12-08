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
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import static de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests.checkForDuplicateExtensions;
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
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void supportsNullCompressionMethod() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        byte[] compression = clientHelloMessage.getCompressions().getValue();
        boolean containsZero = false;
        for (byte i : compression) {
            if (i == 0) {
                containsZero = true;
            }
        }
        assertTrue("ClientHello does not contain compression method null", containsZero);
    }
    
    @Test
    @RFC(number = 7457, section = "2.6.  Compression Attacks: CRIME, TIME, and BREACH")
    @TestDescription("The CRIME attack [...] (CVE-2012-4929) allows an active attacker to " +
            "decrypt ciphertext (specifically, cookies) when TLS is used with TLS- " +
            "level compression.")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void offersNonNullCompressionMethod() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        byte[] compression = clientHelloMessage.getCompressions().getValue();
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
    @TestDescription("The client uses the \"signature_algorithms\" extension to indicate to " +
            "the server which signature/hash algorithm pairs may be used in " +
            "digital signatures.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
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
                case GOST12:
                    //the peer does not have to add algorithms for these
                    //explicitly
                    foundMatch = true;
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
    
    @Test
    @TestDescription("There MUST NOT be more than one extension of the same type. [...]" +
            "The \"anonymous\" value is meaningless in this context but used in " +
            "Section 7.4.3.  It MUST NOT appear in this extension.")
    @RFC(number = 5246, section = "7.4.1.4. Hello Extensions and 7.4.1.4.1. Signature Algorithms")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void checkExtensions() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        checkForDuplicateExtensions(clientHelloMessage);
        SignatureAndHashAlgorithmsExtensionMessage sigHashExtension = context.getReceivedClientHelloMessage().getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        if(sigHashExtension != null) {
            List<SignatureAndHashAlgorithm> algorithmPairs = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(sigHashExtension.getSignatureAndHashAlgorithms().getValue());
            List<SignatureAndHashAlgorithm> anonAlgorithms = algorithmPairs.stream().filter(algo -> {return algo.getSignatureAlgorithm() == SignatureAlgorithm.ANONYMOUS;}).collect(Collectors.toList());
            assertTrue("Client offered anonymous signature algorithms:" + anonAlgorithms.parallelStream().map(Enum::name).collect(Collectors.joining(",")), anonAlgorithms.isEmpty());
        }
    }
        
    private boolean providedSignatureAlgorithm(SignatureAlgorithm requiredAlgorithm) {
        SignatureAndHashAlgorithmsExtensionMessage sigHashExtension = context.getReceivedClientHelloMessage().getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        List<SignatureAndHashAlgorithm> algorithmPairs = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(sigHashExtension.getSignatureAndHashAlgorithms().getValue());
        return algorithmPairs.stream().anyMatch(algoirthmPair -> algoirthmPair.getSignatureAlgorithm() == requiredAlgorithm);
    }
}
