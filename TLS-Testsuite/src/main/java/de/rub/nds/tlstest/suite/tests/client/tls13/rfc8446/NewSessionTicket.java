/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;

@ClientTest
public class NewSessionTicket extends Tls13Test {

    @AnvilTest(id = "8446-b7XLVJA8Pn")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void ignoresUnknownNewSessionTicketExtension(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new SendAction(new NewSessionTicketMessage()));

        // we use a GREASE extension and overwrite its type
        // there are separate tests with GREASE groups
        GreaseExtensionMessage unknownExtension =
                new GreaseExtensionMessage(ExtensionType.GREASE_00, 25);
        unknownExtension.setExtensionType(Modifiable.explicit(new byte[] {0x44, 0x23}));

        NewSessionTicketMessage msg =
                ((NewSessionTicketMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.NEW_SESSION_TICKET));
        msg.addExtension(unknownExtension);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
        assertFalse(
                Validator.socketClosed(state),
                "The connection was closed upon receiving the NewSessionTicket message");
    }
}
