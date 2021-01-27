/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertTrue;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.1.1 Cryptographic Negotiation")
public class CryptographicNegotiation extends Tls13Test {
    
    public List<DerivationParameter> getUnsupportedGroups(DerivationScope scope) {
        List<DerivationParameter> unsupportedGroups = new LinkedList<>();
        List<NamedGroup> supportedTls13Groups = context.getSiteReport().getSupportedTls13Groups();
        NamedGroup.getImplemented().stream().filter(group -> !supportedTls13Groups.contains(group))
                .forEach(unsupportedGroup -> unsupportedGroups.add(new NamedGroupDerivation(unsupportedGroup)));
        return unsupportedGroups;
    }

    @TlsTest(description = "If the server is unable to negotiate a supported set of parameters " +
            "(i.e., there is no overlap between the client and server parameters), it MUST abort " +
            "the handshake with either a \"handshake_failure\" or \"insufficient_security\" fatal alert (see Section 6).")
    @ExplicitValues(affectedTypes = DerivationType.NAMED_GROUP, methods = "getUnsupportedGroups")
    @Interoperability(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.HIGH)
    public void noOverlappingParameters(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = new ClientHelloMessage(config);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }

            AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
            assertTrue(
                    AssertMsgs.UnexpectedAlertDescription,
                    description == AlertDescription.HANDSHAKE_FAILURE || description == AlertDescription.INSUFFICIENT_SECURITY
            );
        });
    }
   

}
