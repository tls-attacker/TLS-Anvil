package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("dtls12")
public class DoS extends Dtls12Test {

    @Tag("Test6")
    @AnvilTest(id = "6347-76Jna7IPv8")
    /**
     * In this test will be tested that in every Record is the same {@link ProtocolVersion} is used.
     */
    public void versionForPacketFormating(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {

        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.FULL);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            ProtocolVersion values = null;

                            for (ReceivingAction action :
                                    i.getWorkflowTrace().getReceivingActions()) {
                                if (action.getReceivedRecords() != null) {
                                    for (Record record : action.getReceivedRecords()) {
                                        if (values == null) {
                                            values =
                                                    ProtocolVersion.getProtocolVersion(
                                                            record.getProtocolVersion().getValue());
                                        }
                                        assertTrue(
                                                values.toString()
                                                        + " != "
                                                        + ProtocolVersion.getProtocolVersion(
                                                                        record.getProtocolVersion()
                                                                                .getValue())
                                                                .toString(),
                                                values.compare(
                                                                ProtocolVersion.getProtocolVersion(
                                                                        record.getProtocolVersion()
                                                                                .getValue()))
                                                        == 0);
                                    }
                                }
                            }
                        });
    }
}
