package de.rub.nds.tlstest.suite.tests.tls12.server.rfc4492;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;


@RFC(number = 4492, section = "4. TLS Extensions for ECC")
@ServerTest
public class TLSExtensionForECC extends Tls12Test {

    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.")
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH )
    public void ECExtensionWithoutECCCipher(WorkflowRunner runner) {
        List<boolean[]> configTupel = new ArrayList<boolean[]>(){
            {
                add(new boolean[]{true, true});
                add(new boolean[]{false, true});
                add(new boolean[]{true, false});
            }
        };

        runner.replaceSupportedCiphersuites = true;
        AnnotatedStateContainer container = new AnnotatedStateContainer();

        for (boolean[] i: configTupel) {
            Config c = context.getConfig().createConfig();

            c.setAddEllipticCurveExtension(i[0]);
            c.setAddECPointFormatExtension(i[1]);

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    new SendAction(new ClientHelloMessage(c)),
                    new ReceiveAction(new AlertMessage(c))
            );

            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(i -> {
            assertTrue(i.getWorkflowTrace().executedAsPlanned());

            AlertMessage message = WorkflowTraceUtil.getFirstReceivedMessage(AlertMessage.class, i.getWorkflowTrace());
            assertNotNull(message);
            assertEquals(AlertLevel.FATAL.getValue(), message.getLevel().getValue().byteValue());
        });
    }
}
