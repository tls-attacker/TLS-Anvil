package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7919;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import static org.junit.Assert.assertTrue;

@ClientTest
@Tag("dheshare")
public class FfDheShare extends Tls12Test {

        @RFC(number = 7919, section = "3. Client Behavior")
        @TlsTest(description = "[...] the client MUST verify that dh_Ys is in the range 1 < "
                        + "dh_Ys < dh_p - 1.  If dh_Ys is not in this range, the client MUST "
                        + "terminate the connection with a fatal handshake_failure(40) alert.")
        @ModelFromScope(baseModel = ModelType.CERTIFICATE)
        @ScopeExtensions(BasicDerivationType.FFDHE_SHARE_OUT_OF_BOUNDS)
        @HandshakeCategory(SeverityLevel.INFORMATIONAL)
        @ComplianceCategory(SeverityLevel.HIGH)
        @AlertCategory(SeverityLevel.MEDIUM)
        @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
        public void shareOutOfBounds(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
                Config c = getPreparedConfig(argumentAccessor, runner);
                WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(
                                WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_HELLO_DONE);
                workflowTrace.addTlsActions(new SendAction(ActionOption.MAY_FAIL, new ServerHelloDoneMessage()),
                                new ReceiveAction(new AlertMessage()));
                DHEServerKeyExchangeMessage SKE = (DHEServerKeyExchangeMessage) WorkflowTraceUtil
                                .getLastSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
                byte[] publicShare = c.getDefaultServerDhPublicKey().toByteArray();
                SKE.setPublicKey(publicShare);
                SKE.getPublicKey().setModification(new ByteArrayExplicitValueModification(publicShare));

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
