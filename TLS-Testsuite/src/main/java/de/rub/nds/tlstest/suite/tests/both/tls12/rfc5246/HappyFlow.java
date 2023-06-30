/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/** Runs a benign handshake with all default derivations to identify parameter-related bugs. */
@Tag("happyflow12")
@RFC(number = 5246, section = "7.3.  Handshake Protocol Overview")
public class HappyFlow extends Tls12Test {

    @AnvilTest(
            description =
                    "A benign handshake executed with all parameter combinations "
                            + " that affect a regular handshake")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.HIGH)
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    public void happyFlow(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        SignatureAndHashAlgorithm selectedSigAndHash;
        CertificateKeyPair selectedCertificate;

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            boolean receivedAlert =
                                    WorkflowTraceUtil.didReceiveMessage(
                                            ProtocolMessageType.ALERT, i.getWorkflowTrace());
                            if (receivedAlert) {
                                AlertMessage alert =
                                        (AlertMessage)
                                                WorkflowTraceUtil.getFirstReceivedMessage(
                                                        ProtocolMessageType.ALERT,
                                                        i.getWorkflowTrace());
                                LOGGER.error(
                                        "Received Alert "
                                                + AlertDescription.getAlertDescription(
                                                        alert.getDescription().getValue())
                                                + " for Happy Flow using derivations:\n"
                                                + derivationContainer.toString()
                                                + "\nWorkflowTrace:\n"
                                                + i.getWorkflowTrace().toString());
                            }
                            Validator.executedAsPlanned(i);
                        });
    }
}
