/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8422, section = "5.4 Server Key Exchange")
@ClientTest
public class ServerKeyExchange extends Tls12Test {

    @AnvilTest(
            description =
                    "The client verifies the signature (when present) and retrieves the "
                            + "server's elliptic curve domain parameters and ephemeral ECDH public "
                            + "key from the ServerKeyExchange message.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ALL12},
            requiresServerKeyExchMsg = true)
    @ScopeExtensions(TlsParameterType.SIGNATURE_BITMASK)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void invalidServerKeyExchangeSignature(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = derivationContainer.buildBitmask();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        ServerKeyExchangeMessage serverKeyExchangeMsg =
                (ServerKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchangeMsg.setSignature(Modifiable.xor(bitmask, 0));

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            if (serverKeyExchangeMsg.getSignatureLength().getValue()
                                    < bitmask.length) {
                                // we can't determine the ECDSA signature length beforehand
                                // as trailing zeros may be stripped - the manipulation won't be
                                // applied in these cases which results in false positives
                                i.addAdditionalResultInfo("Bitmask exceeded signature length");
                                return;
                            }
                            Validator.receivedFatalAlert(i);
                        });
    }

    public List<DerivationParameter> getUnproposedNamedGroups(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        NamedGroup.getImplemented().stream()
                .filter(group -> group.isCurve())
                .filter(
                        curve ->
                                !context.getFeatureExtractionResult()
                                        .getNamedGroups()
                                        .contains(curve))
                .forEach(
                        unofferedCurve ->
                                parameterValues.add(new NamedGroupDerivation(unofferedCurve)));
        return parameterValues;
    }

    public List<DerivationParameter<TlsAnvilConfig, CertificateKeyPair>>
            getCertsIncludingUnsupportedPkGroups(DerivationScope scope) {
        CertificateDerivation certDerivation =
                (CertificateDerivation) DerivationFactory.getInstance(TlsParameterType.CERTIFICATE);
        return certDerivation.getApplicableCertificates(context, scope, true);
    }

    @AnvilTest(
            description =
                    "A possible reason for a "
                            + "fatal handshake failure is that the client's capabilities for "
                            + "handling elliptic curves and point formats are exceeded")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ECDH},
            requiresServerKeyExchMsg = true)
    @ExplicitValues(
            affectedIdentifiers = {"NAMED_GROUP", "CERTIFICATE"},
            methods = {"getUnproposedNamedGroups", "getCertsIncludingUnsupportedPkGroups"})
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsUnproposedNamedGroup(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }

    public boolean isStaticEcdhCipherSuite(CipherSuite cipherSuite) {
        return AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeEcdh()
                && !cipherSuite.isEphemeral();
    }

    public List<DerivationParameter> getEcdhCertsForUnproposedGroups(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        CertificateByteChooser.getInstance().getCertificateKeyPairList().stream()
                .filter(
                        certKeyPair -> {
                            return (certKeyPair.getCertPublicKeyType() == CertificateKeyType.ECDH
                                            || certKeyPair.getCertPublicKeyType()
                                                    == CertificateKeyType.ECDSA)
                                    && !context.getFeatureExtractionResult()
                                            .getNamedGroups()
                                            .contains(certKeyPair.getPublicKeyGroup());
                        })
                .forEach(
                        certKeyPair -> parameterValues.add(new CertificateDerivation(certKeyPair)));
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "A possible reason for a "
                            + "fatal handshake failure is that the client's capabilities for "
                            + "handling elliptic curves and point formats are exceeded")
    @ModelFromScope(modelType = "GENERIC")
    @ScopeExtensions(TlsParameterType.CERTIFICATE)
    @ScopeLimitations(TlsParameterType.NAMED_GROUP)
    @ExplicitValues(
            affectedIdentifiers = "CERTIFICATE",
            methods = "getEcdhCertsForUnproposedGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @DynamicValueConstraints(
            affectedIdentifiers = "CIPHER_SUITE",
            methods = "isStaticEcdhCipherSuite")
    public void acceptsUnproposedNamedGroupStatic(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }

    @AnvilTest(
            description =
                    "The client verifies the signature (when present) and retrieves the "
                            + "server's elliptic curve domain parameters and ephemeral ECDH public "
                            + "key from the ServerKeyExchange message.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ALL12},
            requiresServerKeyExchMsg = true)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsMissingSignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        ServerKeyExchangeMessage serverKeyExchange =
                (ServerKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setSignature(Modifiable.explicit(new byte[0]));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }

    public boolean isNotAnonCipherSuite(CipherSuite cipherSuite) {
        return !cipherSuite.isAnon();
    }

    @AnvilTest(
            description =
                    "The client verifies the signature (when present) and retrieves the "
                            + "server's elliptic curve domain parameters and ephemeral ECDH public "
                            + "key from the ServerKeyExchange message.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ScopeLimitations(TlsParameterType.SIG_HASH_ALGORIHTM)
    @KeyExchange(
            supported = {KeyExchangeType.ALL12},
            requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(
            affectedIdentifiers = "CIPHER_SUITE",
            methods = "isNotAnonCipherSuite")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsAnonSignatureForNonAnonymousCipherSuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        CipherSuite selectedCipherSuite =
                derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        DigestAlgorithm digest =
                AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12, selectedCipherSuite);
        String digestName = "NONE";
        if (digest != null) {
            digestName = digest.name();
        }
        SignatureAndHashAlgorithm matchingAnon =
                SignatureAndHashAlgorithm.valueOf("ANONYMOUS_" + digestName);
        ServerKeyExchangeMessage serverKeyExchange =
                (ServerKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setSignatureAndHashAlgorithm(
                Modifiable.explicit(matchingAnon.getByteValue()));
        serverKeyExchange.setSignature(Modifiable.explicit(new byte[0]));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }

    public List<DerivationParameter> getUnproposedSignatureAndHashAlgorithms(
            DerivationScope scope) {
        List<DerivationParameter> unsupportedAlgorithms = new LinkedList<>();
        ClientFeatureExtractionResult extractionResult =
                (ClientFeatureExtractionResult) context.getFeatureExtractionResult();
        SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(
                        algorithm ->
                                !extractionResult
                                        .getAdvertisedSignatureAndHashAlgorithms()
                                        .contains(algorithm))
                .filter(
                        algorithm ->
                                algorithm.getSignatureAlgorithm() != SignatureAlgorithm.ANONYMOUS)
                .forEach(
                        algorithm ->
                                unsupportedAlgorithms.add(new SigAndHashDerivation(algorithm)));
        return unsupportedAlgorithms;
    }

    @AnvilTest(
            description =
                    "If the client has offered the \"signature_algorithms\" extension, the "
                            + "signature algorithm and hash algorithm MUST be a pair listed in that "
                            + "extension. ")
    @RFC(number = 5246, section = "7.4.3.  Server Key Exchange Message")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(
            supported = {KeyExchangeType.ALL12},
            requiresServerKeyExchMsg = true)
    @ExplicitValues(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getUnproposedSignatureAndHashAlgorithms")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsUnproposedSignatureAndHash(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }
}
