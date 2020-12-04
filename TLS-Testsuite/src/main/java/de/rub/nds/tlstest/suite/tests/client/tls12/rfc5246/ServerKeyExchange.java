package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8422, section = "5.4 Server Key Exchange")
@ClientTest
public class ServerKeyExchange extends Tls12Test {
    
    @TlsTest(description = "The client must verify the signature of the ServerKeyExchange message")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.CRITICAL)
    @KeyExchange(supported = {KeyExchangeType.ALL12}, requiresServerKeyExchMsg = true)
    @ScopeExtensions(DerivationType.SIGNATURE_BITMASK)
    public void invalidServerKeyExchangeSignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = derivationContainer.buildBitmask();
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        ServerKeyExchangeMessage serverKeyExchangeMsg = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchangeMsg.setSignature(Modifiable.xor(bitmask, 0));
        
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }
    
    public List<DerivationParameter> getUnproposedNamedGroups() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        NamedGroup.getImplemented().stream()
                .filter(group -> group.isCurve())
                .filter(curve -> !context.getSiteReport().getSupportedNamedGroups().contains(curve))
                .forEach(unofferedCurve -> parameterValues.add(new NamedGroupDerivation(unofferedCurve)));
        return parameterValues;
    }

    @TlsTest(description = "A possible reason for a "
            + "fatal handshake failure is that the client's capabilities for "
            + "handling elliptic curves and point formats are exceeded")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.MEDIUM)
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @ExplicitValues(affectedTypes = DerivationType.NAMED_GROUP, methods = "getUnproposedNamedGroups")
    public void acceptsUnproposedNamedGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
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
    @Security(SeverityLevel.CRITICAL)
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    public void acceptsMissingSignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        ECDHEServerKeyExchangeMessage serverKeyExchange = (ECDHEServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
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
    @Security(SeverityLevel.CRITICAL)
    @KeyExchange(supported = {KeyExchangeType.ECDH}, requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isNotAnonCipherSuite")
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
        ECDHEServerKeyExchangeMessage serverKeyExchange = (ECDHEServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setSignatureAndHashAlgorithm(Modifiable.explicit(matchingAnon.getByteValue()));
        serverKeyExchange.setSignature(Modifiable.explicit(new byte[0]));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }
}
