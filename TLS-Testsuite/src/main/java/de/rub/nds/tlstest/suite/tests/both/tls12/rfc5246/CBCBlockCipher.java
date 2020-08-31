package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;


@RFC(number = 5264, section = "6.2.3.2 CBC Block Cipher")
public class CBCBlockCipher extends Tls12Test {

    private ConditionEvaluationResult supportsCBCCipherSuites() {
        List<CipherSuite> suites = new ArrayList<>(context.getSiteReport().getCipherSuites());
        suites.removeIf(i -> !i.isCBC());
        if (suites.size() > 0) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("No CBC Suites are supported");
    }

    @TlsTest(description = "Each uint8 in the padding data " +
            "vector MUST be filled with the padding length value. The receiver " +
            "MUST check this padding and MUST use the bad_record_mac alert to " +
            "indicate padding errors.", securitySeverity = SeverityLevel.HIGH)
    @MethodCondition(method = "supportsCBCCipherSuites")
    public void invalidCBCPadding(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;
        runner.respectConfigSupportedCiphersuites = true;

        List<CipherSuite> suites = CipherSuite.getImplemented();
        suites.removeIf(i -> !i.isCBC());
        c.setDefaultServerSupportedCiphersuites(suites);
        c.setDefaultClientSupportedCiphersuites(suites);

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setPadding(Modifiable.xor(new byte[]{0x01}, 0));

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
            if (msg == null || msg.getDescription().getValue() != AlertDescription.BAD_RECORD_MAC.getValue()) {
                throw new AssertionError("Received non expected alert message with invalid CBC padding");
            }
        });

    }

    @TlsTest(description = "The padding length MUST be such that the total size of the " +
            "GenericBlockCipher structure is a multiple of the cipher’s block " +
            "length. Legal values range from zero to 255, inclusive. This " +
            "length specifies the length of the padding field exclusive of the " +
            "padding_length field itself.", securitySeverity = SeverityLevel.HIGH)
    @MethodCondition(clazz = CBCBlockCipher.class, method = "supportsCBCCipherSuites")
    public void invalidCipherText(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;
        runner.respectConfigSupportedCiphersuites = true;

        List<CipherSuite> suites = CipherSuite.getImplemented();
        suites.removeIf(i -> !i.isCBC());
        c.setDefaultServerSupportedCiphersuites(suites);
        c.setDefaultClientSupportedCiphersuites(suites);

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setCiphertext(Modifiable.xor(new byte[]{0x01}, 0));

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
            if (msg == null || msg.getDescription().getValue() != AlertDescription.BAD_RECORD_MAC.getValue()) {
                throw new AssertionError("Received non expected alert message with invalid CBC padding");
            }
        });
    }


}
