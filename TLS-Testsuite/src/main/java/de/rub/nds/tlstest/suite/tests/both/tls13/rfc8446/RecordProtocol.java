package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

@RFC(number = 8446, section = "5. Record Protocol")
public class RecordProtocol extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send record types not " +
            "defined in this document unless negotiated by some extension. " +
            "If a TLS implementation receives an unexpected record type, " +
            "it MUST terminate the connection with an \"unexpected_message\" alert.")
    public void invalidRecordContentType(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        runner.replaceSupportedCiphersuites = true;

        Config c = this.getConfig();
        WorkflowTrace trace;
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte)0xff));
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            trace = new WorkflowTrace();
            trace.addTlsAction(new SendAction(new ClientHelloMessage(c)));
        } else {
            trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        }

        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstAction(SendAction.class).setRecords(record);
            return null;
        });

        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }


    @TlsTest(description = "If the decryption fails, the receiver MUST " +
            "terminate the connection with a \"bad_record_mac\" alert.", securitySeverity = SeverityLevel.CRITICAL)
    public void invalidAuthTag(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setAuthenticationTag(Modifiable.xor(new byte[]{1}, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setRecords(record);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                appData,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "The length (in bytes) of the following " +
            "TLSPlaintext.fragment. The length MUST NOT exceed 2^14 + 256 bytes. " +
            "An endpoint that receives a record that exceeds this " +
            "length MUST terminate the connection with a \"record_overflow\" alert.", interoperabilitySeverity = SeverityLevel.HIGH)
    @RFC(number = 8446, section = "5.1. Record Layer")
    public void sendRecordWithPlaintextOver2pow14plus1(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;
        runner.useRecordFragmentationDerivation = false;

        c.getDefaultClientConnection().setTimeout(5000);
        c.getDefaultServerConnection().setTimeout(5000);

        ApplicationMessage msg = new ApplicationMessage(c);
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    @TlsTest(description = "If the decryption fails, the receiver MUST " +
            "terminate the connection with a \"bad_record_mac\" alert.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 8446, section = "5.2. Record Payload Protection")
    public void invalidCiphertext(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setCiphertext(Modifiable.xor(new byte[]{1}, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setRecords(record);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                appData,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }


    @TlsTest(description = "The length MUST NOT exceed 2^14 + 256 bytes. " +
            "An endpoint that receives a record that exceeds this " +
            "length MUST terminate the connection with a \"record_overflow\" alert.", interoperabilitySeverity = SeverityLevel.HIGH)
    @RFC(number = 8446, section = "5.2. Record Payload Protection")
    public void sendRecordWithCiphertextOver2pow14plus1(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;
        runner.useRecordFragmentationDerivation = false;

        c.getDefaultClientConnection().setTimeout(5000);
        c.getDefaultServerConnection().setTimeout(5000);

        ApplicationMessage msg = new ApplicationMessage(c);
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 266]));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

}
