/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import static de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests.checkForDuplicateExtensions;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class ClientHello extends Tls12Test {

    @NonCombinatorialAnvilTest(id = "5246-kUgwh5Nkzn")
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

    @NonCombinatorialAnvilTest(id = "5246-iAJbTqtHyt")
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
        return context.getReceivedClientHelloMessage()
                                .getExtension(SignatureAndHashAlgorithmsExtensionMessage.class)
                        == null
                ? ConditionEvaluationResult.disabled(
                        "Target did not sent SignatureAndHashAlgorithms Extension")
                : ConditionEvaluationResult.enabled("");
    }

    @NonCombinatorialAnvilTest(id = "5246-D6cXH2VnPy")
    @MethodCondition(method = "sentSignatureAndHashAlgorithmsExtension")
    public void offeredSignatureAlgorithmsForAllCipherSuites() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        List<CipherSuite> proposedCipherSuites =
                CipherSuite.getCipherSuites(clientHelloMessage.getCipherSuites().getValue());
        proposedCipherSuites =
                proposedCipherSuites.stream()
                        .filter(
                                cipherSuite ->
                                        !cipherSuite.isTls13() && cipherSuite.isRealCipherSuite())
                        .collect(Collectors.toList());
        List<CipherSuite> coveredCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : proposedCipherSuites) {
            boolean foundMatch = false;
            for (X509PublicKeyType keyType :
                    AlgorithmResolver.getSuiteableLeafCertificateKeyType(cipherSuite)) {
                switch (keyType) {
                    case DH:
                    case DSA:
                        if (providedSignatureAlgorithm(SignatureAlgorithm.DSA)) {
                            foundMatch = true;
                        }
                        break;
                    case ECDH_ONLY:
                    case ECDH_ECDSA:
                    case ECMQV:
                        if (providedSignatureAlgorithm(SignatureAlgorithm.ECDSA)
                                || providedSignatureAlgorithm(SignatureAlgorithm.ED25519)
                                || providedSignatureAlgorithm(SignatureAlgorithm.ED448)) {
                            foundMatch = true;
                        }
                        break;
                    case RSA:
                        if (providedSignatureAlgorithm(SignatureAlgorithm.RSA_PKCS1)
                                || providedSignatureAlgorithm(SignatureAlgorithm.RSA_SSA_PSS)
                                || providedSignatureAlgorithm(SignatureAlgorithm.RSA_PSS_RSAE)) {
                            foundMatch = true;
                        }
                        break;
                    case GOST_R3411_2001:
                    case GOST_R3411_2012:
                        // the peer does not have to add algorithms for these
                        // explicitly
                        foundMatch = true;
                        break;
                }
            }
            if (foundMatch) {
                coveredCipherSuites.add(cipherSuite);
            }
        }
        proposedCipherSuites.removeAll(coveredCipherSuites);
        assertTrue(
                "Client did not provide a SignatureAlgorithm for all cipher suites "
                        + proposedCipherSuites.parallelStream()
                                .map(Enum::name)
                                .collect(Collectors.joining(",")),
                proposedCipherSuites.isEmpty());
    }

    @NonCombinatorialAnvilTest(id = "5246-booCra12We")
    @Tag("new")
    public void checkExtensions() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        checkForDuplicateExtensions(clientHelloMessage);
        SignatureAndHashAlgorithmsExtensionMessage sigHashExtension =
                context.getReceivedClientHelloMessage()
                        .getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        if (sigHashExtension != null) {
            List<SignatureAndHashAlgorithm> algorithmPairs =
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                            sigHashExtension.getSignatureAndHashAlgorithms().getValue());
            List<SignatureAndHashAlgorithm> anonAlgorithms =
                    algorithmPairs.stream()
                            .filter(algo -> algo.getSignatureAlgorithm() == null)
                            .collect(Collectors.toList());
            assertTrue(
                    "Client offered anonymous signature algorithms:"
                            + anonAlgorithms.parallelStream()
                                    .map(Enum::name)
                                    .collect(Collectors.joining(",")),
                    anonAlgorithms.isEmpty());
        }
    }

    private boolean providedSignatureAlgorithm(SignatureAlgorithm requiredAlgorithm) {
        SignatureAndHashAlgorithmsExtensionMessage sigHashExtension =
                context.getReceivedClientHelloMessage()
                        .getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        List<SignatureAndHashAlgorithm> algorithmPairs =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                        sigHashExtension.getSignatureAndHashAlgorithms().getValue());
        return algorithmPairs.stream()
                .anyMatch(
                        algoirthmPair ->
                                algoirthmPair.getSignatureAlgorithm() == requiredAlgorithm);
    }
}
