/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7465;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class RC4Ciphersuites extends Tls12Test {

    public boolean isRC4CipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.name().contains("RC4");
    }

    @NonCombinatorialAnvilTest
    public void offersRC4Ciphersuites() {
        List<CipherSuite> supported =
                new ArrayList<>(this.context.getFeatureExtractionResult().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));
        if (supported.size() > 0) {
            throw new AssertionError("Client supports RC4 Ciphersuites");
        }
    }

    @AnvilTest
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isRC4CipherSuite")
    @EnforcedSenderRestriction
    public void selectRC4CipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
