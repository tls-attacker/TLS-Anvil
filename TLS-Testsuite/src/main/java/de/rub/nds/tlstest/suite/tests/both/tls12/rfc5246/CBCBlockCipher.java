/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.*;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.List;
import org.junit.jupiter.api.Tag;

public class CBCBlockCipher extends Tls12Test {

    // tests are supposed to test validity with different padding sizes etc
    // splitting fragments into too small records would interfere with this
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    private int getResultingPaddingSize(
            boolean isEncryptThenMac,
            int applicationMessageContentLength,
            CipherSuite cipherSuite,
            ProtocolVersion targetVersion) {
        int blockSize = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(targetVersion, cipherSuite).getMacLength();
        if (isEncryptThenMac) {
            return blockSize - (applicationMessageContentLength % blockSize);
        } else {
            return blockSize - ((applicationMessageContentLength + macSize) % blockSize);
        }
    }

    private boolean resultsInPlausiblePadding(
            int resultingPaddingSize,
            int selectedBitmaskBytePosition,
            int selectedBitPosition,
            int selectedAppMsgLength) {

        if ((selectedBitmaskBytePosition + 1) == resultingPaddingSize
                && (1 << selectedBitPosition) == (resultingPaddingSize - 1)) {
            // padding appears to be only the lengthfield byte
            return false;
        } else if (resultingPaddingSize == 1
                && selectedBitmaskBytePosition == 0
                && (resultingPaddingSize ^ (1 << selectedBitPosition))
                        == AppMsgLengthDerivation.getAsciiLetter()
                && selectedAppMsgLength >= AppMsgLengthDerivation.getAsciiLetter()) {
            // only one byte of padding (lengthfield) gets modified in a way
            // that it matches the ASCII contents of the AppMsg data
            return false;
        }
        return true;
    }

    @AnvilTest(id = "5246-RNB9LX21i9")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameters({@IncludeParameter("APP_MSG_LENGHT")})
    @ValueConstraints({@ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC")})
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidCBCPadding(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        int appMsgLength = c.getDefaultApplicationMessageData().length();
        int paddingSize =
                getResultingPaddingSize(
                        c.isAddEncryptThenMacExtension(),
                        appMsgLength,
                        c.getDefaultSelectedCipherSuite(),
                        c.getDefaultSelectedProtocolVersion());

        // iterate though every bit position
        // we do this instead of having the bit position a derivation, since parameter generation
        // takes too long with this setup
        for (int i = 0; i < paddingSize; i++) {
            for (int j = 0; j < 8; j++) {
                if (!resultsInPlausiblePadding(paddingSize, i, j, appMsgLength)) {
                    continue;
                }
                byte[] modificationBitmask = new byte[i + 1];
                modificationBitmask[i] = (byte) (1 << j);
                testCase.addAdditionalResultInfo(
                        "failed at modified padding byte " + i + " and bit " + j);

                Record record = new Record();
                record.setComputations(new RecordCryptoComputations());
                record.getComputations().setPadding(Modifiable.xor(modificationBitmask, 0));

                ApplicationMessage appData = new ApplicationMessage();
                appData.setData(
                        Modifiable.explicit(c.getDefaultApplicationMessageData().getBytes()));

                SendAction sendAction = new SendAction(appData);
                sendAction.setConfiguredRecords(List.of(record));

                WorkflowTrace workflowTrace =
                        runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
                workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

                State state = runner.execute(workflowTrace, c);

                WorkflowTrace trace = state.getWorkflowTrace();
                Validator.executedAsPlanned(state, testCase);
                Validator.receivedFatalAlert(state, testCase);

                AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                Validator.testAlertDescription(
                        state, testCase, AlertDescription.BAD_RECORD_MAC, msg);

                if (testCase.getTestResult() == TestResult.FULLY_FAILED
                        || testCase.getTestResult() == TestResult.PARTIALLY_FAILED) {
                    return;
                } else {
                    // remove "failed at" message, if we did not fail
                    testCase.getAdditionalResultInformation()
                            .remove(testCase.getAdditionalResultInformation().size() - 1);
                }
            }
        }
        // set result info null, if still empty
        if (testCase.getAdditionalResultInformation() != null
                && testCase.getAdditionalResultInformation().isEmpty()) {
            testCase.setAdditionalResultInformation(null);
        }
    }

    @AnvilTest(id = "5246-VC1baM1Mn1")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("CIPHERTEXT_BITMASK")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidCipherText(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        if (c.isAddEncryptThenMacExtension()) {
            // modify record bytes as ciphertext is used to compute mac
            record.setProtocolMessageBytes(Modifiable.xor(modificationBitmask, 0));
        } else {
            record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));
        }

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setConfiguredRecords(List.of(record));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC, msg);
        if (msg != null
                && msg.getDescription().getValue()
                        == AlertDescription.DECRYPTION_FAILED_RESERVED.getValue()) {
            // 7.2.2. Error Alerts - decryption_failed_RESERVED
            // This alert was used in some earlier versions of TLS, and may have
            // permitted certain attacks against the CBC mode [CBCATT]. It MUST
            // NOT be sent by compliant implementations.
            throw new AssertionError(
                    "Target sent deprecated decryption_failed_RESERVERD alert in response to invalid Ciphertext");
        }
    }

    @AnvilTest(id = "5246-JBqS2uGywY")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("MAC_BITMASK")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidMAC(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        byte[] bitmask = parameterCombination.buildBitmask();
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setMac(Modifiable.xor(bitmask, 0));

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setConfiguredRecords(List.of(record));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC, msg);
    }

    @AnvilTest(id = "5246-BWb6uwVEte")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @Tag("new")
    public void checkReceivedMac(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        boolean sawCCS = false;
        for (Record record :
                WorkflowTraceResultUtil.getAllReceivedRecords(state.getWorkflowTrace())) {
            if (record.getContentMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                sawCCS = true;
            }
            if (sawCCS && record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
                Record encryptedFin = record;
                assertTrue(
                        encryptedFin.getComputations().getMacValid(),
                        "Finished record MAC invalid - is the SQN correct?");
            } else if (sawCCS
                    && record.getContentMessageType() == ProtocolMessageType.APPLICATION_DATA) {
                Record encryptedFin = record;
                assertTrue(
                        encryptedFin.getComputations().getMacValid(),
                        "App Data record MAC invalid");
            }
        }
    }
}
