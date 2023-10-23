package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6347, section = "4.2.1. Denial-of-Service Countermeasures")
@Tag("dtls12")
public class DoS extends Dtls12Test {

    @Tag("Test6")
    @TlsTest(
            description =
                    "DTLS 1.2 and 1.0 clients MUST use the version solely to indicate packet formatting (which is the same in both DTLS 1.2 and 1.0) and not as part of version negotiation.")
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