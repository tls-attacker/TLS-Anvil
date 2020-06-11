package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;


@RFC(number = 5264, section = "6.2.3.3 AEAD Ciphers")
@ServerTest
public class AEADCiphers extends Tls12Test {

    private ConditionEvaluationResult supportsAEADCiphers() {
        List<CipherSuite> suites = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        suites.removeIf(i -> !i.isAEAD());
        if (suites.size() > 0) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("No AEAD Cipher Suites are supported");
    }

    @TlsTest(description = "If the decryption fails, a fatal bad_record_mac alert MUST be generated.", securitySeverity = SeverityLevel.CRITICAL)
    @MethodCondition(method = "supportsAEADCiphers")
    public void inalidAuthTag(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;
        runner.respectConfigSupportedCiphersuites = true;

        List<CipherSuite> suites = CipherSuite.getImplemented();
        suites.removeIf(i -> !i.isAEAD());
        c.setDefaultClientSupportedCiphersuites(suites);

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setAuthenticationTag(Modifiable.xor(new byte[]{0x01}, 0));

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
            assertTrue(trace.executedAsPlanned());

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
        });
    }

    @TlsTest(description = "If the decryption fails, a fatal bad_record_mac alert MUST be generated.", securitySeverity = SeverityLevel.CRITICAL)
    @MethodCondition(method = "supportsAEADCiphers")
    public void inalidCiphertext(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;
        runner.respectConfigSupportedCiphersuites = true;

        List<CipherSuite> suites = CipherSuite.getImplemented();
        suites.removeIf(i -> !i.isAEAD());
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
            assertTrue(trace.executedAsPlanned());

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
        });
    }


}
