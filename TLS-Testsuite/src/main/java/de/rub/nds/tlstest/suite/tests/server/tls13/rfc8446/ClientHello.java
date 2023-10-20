/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class ClientHello extends Tls13Test {

    @AnvilTest(id = "8446-Ruhj2eLN2t")
    public void includeUnknownCipherSuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.insert(new byte[] {(byte) 0xfe, 0x00}, 0));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(id = "8446-B41SD1Cnr6")
    @EnforcedSenderRestriction
    public void invalidLegacyVersion_higher(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x04}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-fsDXt1hint")
    @EnforcedSenderRestriction
    public void invalidLegacyVersion_lower(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x02}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-hsFoi24Gdh")
    public void invalidLegacyVersion_ssl30(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x00}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-qgJEM4UoBe")
    public void invalidCompression(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setCompressions(Modifiable.explicit(new byte[] {0x01}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest(id = "8446-vtJcLUKtNv")
    public void includeUnknownExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        // we use a Grease Extension for which we modify the type
        GreaseExtensionMessage greaseHelperExtension =
                new GreaseExtensionMessage(ExtensionType.GREASE_00, 32);
        greaseHelperExtension.setExtensionType(
                Modifiable.explicit(new byte[] {(byte) 0xBA, (byte) 0x9F}));

        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        clientHello.addExtension(greaseHelperExtension);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);

                            ServerHelloMessage serverHello =
                                    (ServerHelloMessage)
                                            WorkflowTraceUtil.getFirstReceivedMessage(
                                                    HandshakeMessageType.SERVER_HELLO,
                                                    workflowTrace);
                            for (ExtensionMessage extension : serverHello.getExtensions()) {
                                assertFalse(
                                        "Server negotiated the undefined Extension",
                                        Arrays.equals(
                                                extension.getExtensionType().getValue(),
                                                greaseHelperExtension.getType().getValue()));
                            }
                        });
    }

    // there is an omitSignatureAlgorithms test in SignatureAlgorithms

    @AnvilTest(id = "8446-GZpjQTKUD4")
    @ExcludeParameter("NAMED_GROUP")
    @Tag("new")
    public void omitKeyShareAndSupportedGroups(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddKeyShareExtension(false);
        config.setAddEllipticCurveExtension(false);

        performMissingExtensionTest(config, runner);
    }

    private void performMissingExtensionTest(Config config, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.MISSING_EXTENSION);
                        });
    }

    @AnvilTest(id = "8446-jEEunwNUJ3")
    @ExcludeParameter("NAMED_GROUP")
    @Tag("new")
    public void omitKeyShare(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddKeyShareExtension(false);

        performMissingExtensionTest(config, runner);
    }

    @AnvilTest(id = "8446-KQn4u3Xj4M")
    @Tag("new")
    public void omitSupportedGroups(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddEllipticCurveExtension(false);

        performMissingExtensionTest(config, runner);
    }

    @AnvilTest(id = "8446-Uqrk3dnMz7")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Tag("new")
    public void acceptsCompressionListForLegacyClient(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        config.setDefaultClientSupportedCompressionMethods(
                CompressionMethod.NULL, CompressionMethod.DEFLATE);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }
}
