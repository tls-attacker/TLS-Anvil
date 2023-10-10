/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import static de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests.checkForDuplicateExtensions;
import static de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446.ServerHello.checkForUnproposedExtensions;
import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class ServerHello extends Tls12Test {

    @AnvilTest
    public void serverRandom(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            ServerHelloMessage serverHello =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            ClientHelloMessage clientHello =
                                    trace.getFirstSendMessage(ClientHelloMessage.class);

                            assertFalse(
                                    "ServerHello random equals ClienHello",
                                    Arrays.equals(
                                            clientHello.getRandom().getValue(),
                                            serverHello.getRandom().getValue()));
                        });
    }

    @AnvilTest
    @Tag("new")
    public void checkExtensions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            checkForUnproposedExtensions(
                                    workflowTrace.getFirstReceivedMessage(ServerHelloMessage.class),
                                    workflowTrace.getFirstSendMessage(ClientHelloMessage.class));
                            checkForDuplicateExtensions(
                                    workflowTrace.getFirstReceivedMessage(
                                            ServerHelloMessage.class));
                            if (workflowTrace
                                            .getFirstReceivedMessage(ServerHelloMessage.class)
                                            .getExtensions()
                                    != null) {
                                assertFalse(
                                        "Server sent a Signature Algorithms Extension",
                                        workflowTrace
                                                .getFirstReceivedMessage(ServerHelloMessage.class)
                                                .containsExtension(
                                                        ExtensionType
                                                                .SIGNATURE_AND_HASH_ALGORITHMS));
                            }
                        });
    }
}
