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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.1.2 Client Hello")
public class ClientHello extends Tls13Test {


    @TlsTest(description = "If the list contains cipher suites that the server "
            + "does not recognize, support, or wish to use, the server MUST "
            + "ignore those cipher suites and process the remaining ones as "
            + "usual. [...]"
            + "A server receiving a ClientHello MUST correctly ignore all " 
            + "unrecognized cipher suites, extensions, and other parameters. "
            + "Otherwise, it may fail to interoperate with newer clients.")
    @RFC(number = 8446, section = "4.1.2 Client Hello and 9.3. Protocol Invariants")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    public void includeUnknownCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.insert(new byte[]{(byte) 0xfe, 0x00}, 0));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "In TLS 1.3, the client indicates its version preferences "
            + "in the \"supported_versions\" extension (Section 4.2.1) and the legacy_version "
            + "field MUST be set to 0x0303, which is the version number for TLS 1.2.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void invalidLegacyVersion_higher(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x04}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "In TLS 1.3, the client indicates its version preferences "
            + "in the \"supported_versions\" extension (Section 4.2.1) and the legacy_version "
            + "field MUST be set to 0x0303, which is the version number for TLS 1.2.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void invalidLegacyVersion_lower(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x02}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send a "
            + "ClientHello.legacy_version or ServerHello.legacy_version "
            + "set to 0x0300 or less. Any endpoint receiving a Hello message with "
            + "ClientHello.legacy_version or ServerHello.legacy_version set to 0x0300 "
            + "MUST abort the handshake with a \"protocol_version\" alert.")
    @RFC(number = 8446, section = "D.5. Security Restrictions Related to Backward Compatibility")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void invalidLegacyVersion_ssl30(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x00}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "For every TLS 1.3 ClientHello, this vector MUST contain "
            + "exactly one byte, set to zero, which corresponds to the \"null\" compression method in prior "
            + "versions of TLS. If a TLS 1.3 ClientHello is received with any other value in this field, "
            + "the server MUST abort the handshake with an \"illegal_parameter\" alert.")
    @RFC(number = 8446, section = "4.1.2 Client Hello and 9.3. Protocol Invariants")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void invalidCompression(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setCompressions(Modifiable.explicit(new byte[]{0x01}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "Servers MUST ignore unrecognized extensions. [...]"
            + "A server receiving a ClientHello MUST correctly ignore all " 
            + "unrecognized cipher suites, extensions, and other parameters. "
            + "Otherwise, it may fail to interoperate with newer clients.")
    @RFC(number = 8446, section = "4.1.2 Client Hello and 9.3. Protocol Invariants")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void includeUnknownExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        //we use a Grease Extension for which we modify the type
        GreaseExtensionMessage greaseHelperExtension = new GreaseExtensionMessage(ExtensionType.GREASE_00, 32);
        greaseHelperExtension.setExtensionType(Modifiable.explicit(new byte[]{(byte) 0xBA, (byte) 0x9F}));

        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        clientHello.addExtension(greaseHelperExtension);

        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage serverHello = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
            for (ExtensionMessage extension : serverHello.getExtensions()) {
                assertFalse("Server negotiated the undefined Extension", Arrays.equals(extension.getExtensionType().getValue(), greaseHelperExtension.getType().getValue()));
            }
        });
    }
    
    //there is an omitSignatureAlgorithms test in SignatureAlgorithms
    
    @TlsTest(description = "A client is considered to be attempting to negotiate using this " +
        "specification if the ClientHello contains a \"supported_versions\" " +
        "extension with 0x0304 contained in its body.  Such a ClientHello " +
        "message MUST meet the following requirements: [...]" +
        "If not containing a \"pre_shared_key\" extension, it MUST contain " +
        "both a \"signature_algorithms\" extension and a \"supported_groups\" " +
        "extension. [...]" + 
        "If containing a \"supported_groups\" extension, it MUST also contain " +
        "a \"key_share\" extension, and vice versa.[...]" + 
        "Servers receiving a ClientHello which does not conform to these " +
        "requirements MUST abort the handshake with a \"missing_extension\" " +
        "alert.")
    @RFC(number = 8446, section = "9.2.  Mandatory-to-Implement Extensions")
    @ScopeLimitations(DerivationType.NAMED_GROUP)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void omitKeyShareAndSupportedGroups(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddKeyShareExtension(false);
        config.setAddEllipticCurveExtension(false);
        
        performMissingExtensionTest(config, runner);
    }

    private void performMissingExtensionTest(Config config, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            Validator.testAlertDescription(i, AlertDescription.MISSING_EXTENSION);
        });
    }
    
    @TlsTest(description = "A client is considered to be attempting to negotiate using this " +
        "specification if the ClientHello contains a \"supported_versions\" " +
        "extension with 0x0304 contained in its body.  Such a ClientHello " +
        "message MUST meet the following requirements: [...]" +
        "If not containing a \"pre_shared_key\" extension, it MUST contain " +
        "both a \"signature_algorithms\" extension and a \"supported_groups\" " +
        "extension. [...]" + 
        "If containing a \"supported_groups\" extension, it MUST also contain " +
        "a \"key_share\" extension, and vice versa.[...]" + 
        "Servers receiving a ClientHello which does not conform to these " +
        "requirements MUST abort the handshake with a \"missing_extension\" " +
        "alert.")
    @RFC(number = 8446, section = "9.2.  Mandatory-to-Implement Extensions")
    @ScopeLimitations(DerivationType.NAMED_GROUP)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void omitKeyShare(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddKeyShareExtension(false);
        
        performMissingExtensionTest(config, runner);
    }
    
    @TlsTest(description = "A client is considered to be attempting to negotiate using this " +
        "specification if the ClientHello contains a \"supported_versions\" " +
        "extension with 0x0304 contained in its body.  Such a ClientHello " +
        "message MUST meet the following requirements: [...]" +
        "If not containing a \"pre_shared_key\" extension, it MUST contain " +
        "both a \"signature_algorithms\" extension and a \"supported_groups\" " +
        "extension. [...]" + 
        "If containing a \"supported_groups\" extension, it MUST also contain " +
        "a \"key_share\" extension, and vice versa.[...]" + 
        "Servers receiving a ClientHello which does not conform to these " +
        "requirements MUST abort the handshake with a \"missing_extension\" " +
        "alert.")
    @RFC(number = 8446, section = "9.2.  Mandatory-to-Implement Extensions")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void omitSupportedGroups(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddEllipticCurveExtension(false);
        
        performMissingExtensionTest(config, runner);
    }
    
    @TlsTest(description = "Note that TLS 1.3 servers might receive TLS 1.2 or prior ClientHellos which contain other compression methods and (if negotiating such a prior version) MUST follow the procedures for the appropriate prior version of TLS.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void acceptsCompressionListForLegacyClient(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        config.setDefaultClientSupportedCompressionMethods(CompressionMethod.NULL, CompressionMethod.DEFLATE);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }
}
