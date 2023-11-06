/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class NewSessionTicket extends Tls13Test {

    @AnvilTest(id = "8446-b7XLVJA8Pn")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void ignoresUnknownNewSessionTicketExtension(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new SendAction(new NewSessionTicketMessage()));

        // we use a GREASE extension and overwrite its type
        // there are separate tests with GREASE groups
        GreaseExtensionMessage unknownExtension =
                new GreaseExtensionMessage(ExtensionType.GREASE_00, 25);
        unknownExtension.setExtensionType(Modifiable.explicit(new byte[] {0x44, 0x23}));

        NewSessionTicketMessage msg =
                workflowTrace.getFirstSendMessage(NewSessionTicketMessage.class);
        msg.addExtension(unknownExtension);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertFalse(
                                    "The connection was closed upon receiving the NewSessionTicket message",
                                    Validator.socketClosed(i));
                        });
    }
}
