/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ExcludeParameters;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.anvil.TlsTestCase;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class CryptographicNegotiation extends Tls13Test {

    @AnvilTest
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS"),
        @ExcludeParameter("NAMED_GROUP")
    })
    // Todo: add 'Groups' to method name
    public void noOverlappingParameters(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = new ClientHelloMessage(config);

        // set up an undefined group and key share
        EllipticCurvesExtensionMessage eccExtension =
                chm.getExtension(EllipticCurvesExtensionMessage.class);
        eccExtension.setSupportedGroups(Modifiable.explicit(NamedGroup.GREASE_00.getValue()));
        KeyShareExtensionMessage keyShareExtension =
                chm.getExtension(KeyShareExtensionMessage.class);
        keyShareExtension.setKeyShareListBytes(
                Modifiable.explicit(new byte[] {0x0A, 0x0A, 0x00, 0x02, 0x12, 0x34}));

        WorkflowTrace trace = buildWorkflowTrace(chm);

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            validateResult(i, trace);
                        });
    }

    @AnvilTest
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_CIPHER_SUITES"),
        @ExcludeParameter("CIPHER_SUITE")
    })
    @Tag("new")
    public void noOverlappingParametersCipherSuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = new ClientHelloMessage(config);
        chm.setCipherSuites(Modifiable.explicit(CipherSuite.GREASE_00.getByteValue()));

        WorkflowTrace trace = buildWorkflowTrace(chm);

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            validateResult(i, trace);
                        });
    }

    private void validateResult(TlsTestCase i, WorkflowTrace trace) {
        Validator.receivedFatalAlert(i);
        AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
        if (alert == null) {
            return;
        }

        // todo add testAlertDescription for multiple allowed alerts
        // also required for FFDHE tests
        AlertDescription description =
                AlertDescription.getAlertDescription(alert.getDescription().getValue());
        if (description != AlertDescription.HANDSHAKE_FAILURE
                && description != AlertDescription.INSUFFICIENT_SECURITY) {
            i.setTestResult(TestResult.CONCEPTUALLY_SUCCEEDED);
            i.addAdditionalResultInfo("Alert was not Handshake Failure or Insufficient Security");
        }
    }

    private WorkflowTrace buildWorkflowTrace(ClientHelloMessage chm) {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(chm), new ReceiveAction(new AlertMessage()));
        return trace;
    }
}
