package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
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
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import org.junit.jupiter.api.Tag;

@RFC(number = 8422, section = "5.4 Server Key Exchange")
@ClientTest
public class ServerKeyExchange extends Tls12Test {

    @TlsTest(description = "The client must verify the signature of the ServerKeyExchange message")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ALL12}, requiresServerKeyExchMsg = true)
    @ScopeExtensions(DerivationType.SIGNATURE_BITMASK)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void invalidServerKeyExchangeSignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = derivationContainer.buildBitmask();

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        ServerKeyExchangeMessage serverKeyExchangeMsg = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchangeMsg.setSignature(Modifiable.xor(bitmask, 0));

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            if(serverKeyExchangeMsg.getSignatureLength().getValue() < bitmask.length) {
                //we can't determine the ECDSA signature length beforehand
                //as trailing zeros may be stripped - the manipulation won't be
                //applied in these cases which results in false positives
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
                .filter(curve -> !context.getSiteReport().getSupportedNamedGroups().contains(curve))
                .forEach(unofferedCurve -> parameterValues.add(new NamedGroupDerivation(unofferedCurve)));
        return parameterValues;
    }
    
    public List<DerivationParameter> getCertsIncludingUnsupportedPkGroups(DerivationScope scope) {
        CertificateDerivation certDerivation = (CertificateDerivation) DerivationFactory.getInstance(DerivationType.CERTIFICATE);
        return certDerivation.getApplicableCertificates(context, scope, true);
    }

    @TlsTest(description = "A possible reason for a "
            + "fatal handshake failure is that the client's capabilities for "
            + "handling elliptic curves and point formats are exceeded")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    @ExplicitValues(affectedTypes = {DerivationType.NAMED_GROUP, DerivationType.CERTIFICATE}, methods = {"getUnproposedNamedGroups", "getCertsIncludingUnsupportedPkGroups"})
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsUnproposedNamedGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }
    
    public boolean isStaticEcdhCipherSuite(CipherSuite cipherSuite) {
        return AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeEcdh() &&
                !cipherSuite.isEphemeral();
    }
    
    public List<DerivationParameter> getEcdhCertsForUnproposedGroups(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        CertificateByteChooser.getInstance().getCertificateKeyPairList().stream().filter(certKeyPair -> {
            return (certKeyPair.getCertPublicKeyType() == CertificateKeyType.ECDH || certKeyPair.getCertPublicKeyType() == CertificateKeyType.ECDSA)
                    && !context.getSiteReport().getSupportedNamedGroups().contains(certKeyPair.getPublicKeyGroup());
        }).forEach(certKeyPair -> parameterValues.add(new CertificateDerivation(certKeyPair)));
        return parameterValues;
    }
    
    @TlsTest(description = "A possible reason for a "
            + "fatal handshake failure is that the client's capabilities for "
            + "handling elliptic curves and point formats are exceeded")
    @ModelFromScope(baseModel = ModelType.GENERIC)
    @ScopeExtensions(DerivationType.CERTIFICATE)
    @ScopeLimitations(DerivationType.NAMED_GROUP)
    @ExplicitValues(affectedTypes = DerivationType.CERTIFICATE, methods = "getEcdhCertsForUnproposedGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isStaticEcdhCipherSuite")
    public void acceptsUnproposedNamedGroupStatic(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }

    @TlsTest(description = "The client verifies the signature (when present) and retrieves the "
            + "server's elliptic curve domain parameters and ephemeral ECDH public "
            + "key from the ServerKeyExchange message.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ALL12}, requiresServerKeyExchMsg = true)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsMissingSignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        ServerKeyExchangeMessage serverKeyExchange = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setSignature(Modifiable.explicit(new byte[0]));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }

    public boolean isNotAnonCipherSuite(CipherSuite cipherSuite) {
        return !cipherSuite.isAnon();
    }

    @TlsTest(description = "The client verifies the signature (when present) and retrieves the "
            + "server's elliptic curve domain parameters and ephemeral ECDH public "
            + "key from the ServerKeyExchange message.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeLimitations(DerivationType.SIG_HASH_ALGORIHTM)
    @KeyExchange(supported = {KeyExchangeType.ALL12}, requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isNotAnonCipherSuite")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsAnonSignatureForNonAnonymousCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        CipherSuite selectedCipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        DigestAlgorithm digest = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS12, selectedCipherSuite);
        String digestName = "NONE";
        if (digest != null) {
            digestName = digest.name();
        }
        SignatureAndHashAlgorithm matchingAnon = SignatureAndHashAlgorithm.valueOf("ANONYMOUS_" + digestName);
        ServerKeyExchangeMessage serverKeyExchange = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setSignatureAndHashAlgorithm(Modifiable.explicit(matchingAnon.getByteValue()));
        serverKeyExchange.setSignature(Modifiable.explicit(new byte[0]));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }
    
    public List<DerivationParameter> getUnproposedSignatureAndHashAlgorithms(DerivationScope scope) {
        List<DerivationParameter> unsupportedAlgorithms = new LinkedList<>();
        SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(algorithm -> !TestContext.getInstance().getSiteReport().getSupportedSignatureAndHashAlgorithms().contains(algorithm))
                .filter(algorithm -> algorithm.getSignatureAlgorithm() != SignatureAlgorithm.ANONYMOUS)
                .forEach(algorithm -> unsupportedAlgorithms.add(new SigAndHashDerivation(algorithm)));
        return unsupportedAlgorithms;
    }
    
    @TlsTest(description = "If the client has offered the \"signature_algorithms\" extension, the "
            + "signature algorithm and hash algorithm MUST be a pair listed in that "
            + "extension. ")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = {KeyExchangeType.ALL12}, requiresServerKeyExchMsg = true)
    @ExplicitValues(affectedTypes = DerivationType.SIG_HASH_ALGORIHTM, methods = "getUnproposedSignatureAndHashAlgorithms")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void acceptsUnproposedSignatureAndHash(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }
}
