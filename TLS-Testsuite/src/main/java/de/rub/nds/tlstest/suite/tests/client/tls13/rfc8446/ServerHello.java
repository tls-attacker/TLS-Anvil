/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Random;

@ClientTest
public class ServerHello extends Tls13Test {

    @AnvilTest(id = "8446-zgsrCx4EDP")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void testSessionId(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        sharedSessionIdTest(workflowTrace, runner, testCase);
    }

    public static void sharedSessionIdTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);

        // WolfSSL expects 32 bytes - to be determined if this is correct behavior
        byte[] dummySessionId = new byte[32];
        dummySessionId[0] = (byte) 0xFF;
        dummySessionId[16] = (byte) 0xFF;
        sh.setSessionId(Modifiable.explicit(dummySessionId));

        State state = runner.execute(workflowTrace, runner.getPreparedConfig());

        WorkflowTrace trace = state.getWorkflowTrace();
        if (trace.getLastReceivedMessage(ClientHelloMessage.class) != null
                && trace.getLastReceivedMessage(ClientHelloMessage.class)
                                .getSessionIdLength()
                                .getValue()
                        == 0) {
            testCase.addAdditionalResultInfo("Client did not set SessionID");
        }
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, msg);
    }

    @AnvilTest(id = "8446-2yeDE1Bso6")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExcludeParameter("CIPHER_SUITE")
    public void testCipherSuite(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setSelectedCipherSuite(Modifiable.explicit(CipherSuite.GREASE_00.getByteValue()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-oEdBWdqUnm")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void testCompressionValue(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        sharedCompressionValueTest(workflowTrace, runner, testCase);
    }

    public static void sharedCompressionValueTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setSelectedCompressionMethod(Modifiable.explicit((byte) 0x01));

        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-TyxxKdqwv3")
    @ModelFromScope(modelType = "CERTIFICATE")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void testRandomDowngradeValue(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), runner);

        Random random = new Random();
        byte[] serverRandom = new byte[32];
        random.nextBytes(serverRandom);

        byte[] downgradeValue = new byte[] {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
        System.arraycopy(downgradeValue, 0, serverRandom, 24, downgradeValue.length);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.addTlsActions(
                new SendAction(ActionOption.MAY_FAIL, new ServerHelloDoneMessage()),
                new ReceiveAction(new AlertMessage()));

        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .setRandom(Modifiable.explicit(serverRandom));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, msg);
    }
}
