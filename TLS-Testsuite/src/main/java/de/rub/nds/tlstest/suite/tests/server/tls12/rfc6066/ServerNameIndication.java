package de.rub.nds.tlstest.suite.tests.server.tls12.rfc6066;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.List;

@RFC(number = 6066, section = "3. Server Name Indication")
@ServerTest
public class ServerNameIndication extends Tls12Test {

    @TlsTest(description = "The ServerNameList MUST NOT contain more than one name of the same " +
            "name_type.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void moreThanOneNameOfTheSameType(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        c.setAddServerNameIndicationExtension(true);

        runner.replaceSupportedCiphersuites = true;
        List<SNIEntry> entries = c.getDefaultClientSNIEntryList();
        SNIEntry entry = entries.get(0);
        SNIEntry newEntry = new SNIEntry(entry.getName(), entry.getType());

        c.setDefaultClientSNIEntries(entry, newEntry);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
