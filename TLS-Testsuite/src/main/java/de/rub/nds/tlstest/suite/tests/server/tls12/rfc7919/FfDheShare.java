package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7919;

import java.math.BigInteger;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import de.rub.nds.modifiablevariable.biginteger.BigIntegerExplicitValueModification;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerMultiplyModification;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerShiftLeftModification;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@ServerTest
@Tag("dheshare")
public class FfDheShare extends Tls12Test {

    @RFC(number = 7919, section = "4. Server Behavior")
    @TlsTest(description = "[...]the server MUST verify that 1 < dh_Yc < dh_p - 1."
            + "If dh_Yc is out of range, the server MUST terminate the connection"
            + "with a fatal handshake_failure(40) alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.FFDHE_SHARE_OUT_OF_BOUNDS)
    @ManualConfig(DerivationType.FFDHE_SHARE_OUT_OF_BOUNDS)
    @HandshakeCategory(SeverityLevel.INFORMATIONAL)
    @ComplianceCategory(SeverityLevel.HIGH)
    @KeyExchange(supported = KeyExchangeType.DH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void shareOutOfBounds(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        DHClientKeyExchangeMessage cke = new DHClientKeyExchangeMessage();
        cke.prepareComputations();
        DHClientComputations computations = cke.getComputations();

        ShareOutOfBoundsDerivation share = derivationContainer.getDerivation(ShareOutOfBoundsDerivation.class);
        switch (share.getSelectedValue()) {
            case SHARE_IS_ONE:
                c.setDefaultClientDhPrivateKey(BigInteger.ZERO);
                c.setDefaultClientDhPublicKey(BigInteger.ONE);
                break;
            case SHARE_PLUS_P:
                // multiply modulus by 2^64
                // Chance that public share is below original p is 1/2^64
                // TODO: would be nice if we could always be above this bound, but only barely
                // i.e. share += p; but this would require us to already know p...
                computations.setModulus(Modifiable.shiftLeftBigInteger(64));
                break;
            default:
                throw new UnsupportedOperationException("Unknown type " + share.getSelectedValue());
        }

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE,
                HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsActions(new SendAction(cke), new SendAction(ActionOption.MAY_FAIL, new ChangeCipherSpecMessage()),new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            //accept both Illegal Parameter and Handshake Failure as RFC 8446 and 7919 demand different alerts
            if(msg != null && !msg.getDescription().getValue().equals(AlertDescription.ILLEGAL_PARAMETER.getValue())) {
                Validator.testAlertDescription(i, AlertDescription.HANDSHAKE_FAILURE, msg);
            }
        });
    }

}
