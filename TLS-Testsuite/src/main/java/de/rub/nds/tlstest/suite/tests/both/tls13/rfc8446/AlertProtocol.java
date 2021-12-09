package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "6. Alert Protocol")
public class AlertProtocol extends Tls13Test {
    
    @TlsTest(description = "All the alerts listed in Section 6.2 MUST be sent with AlertLevel=fatal and MUST be treated as error alerts when received regardless of the AlertLevel in the message.")
    @ScopeExtensions(DerivationType.ALERT)
    @DynamicValueConstraints(affectedTypes = DerivationType.ALERT, methods = "isMeantToBeFatalLevel")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsFatalAlertsAsFatalHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        performFatalAlertWithWarningLevelTest(trace, runner, config);
    }


    
    @TlsTest(description = "All the alerts listed in Section 6.2 MUST be sent with AlertLevel=fatal and MUST be treated as error alerts when received regardless of the AlertLevel in the message.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.ALERT)
    @DynamicValueConstraints(affectedTypes = DerivationType.ALERT, methods = "isMeantToBeFatalLevel")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsFatalAlertsAsFatalPostHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        performFatalAlertWithWarningLevelTest(trace, runner, config);
    }
    
    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownWarningAlertsAsFatalHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        peformUnknownWarningAlertTest(trace, runner, config);
    }
    
    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownWarningAlertsAsFatalPostHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        peformUnknownWarningAlertTest(trace, runner, config);
    }
    
    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownFatalAlertsAsFatalHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        peformUnknownFatalAlertTest(trace, runner, config);
    }
    
    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownFatalAlertsAsFatalPostHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        peformUnknownFatalAlertTest(trace, runner, config);
    }

    private void peformUnknownFatalAlertTest(WorkflowTrace trace, WorkflowRunner runner, Config config) {
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit((byte)200));
        trace.addTlsAction(new SendAction(alert));
        
        runner.execute(trace, config).validateFinal(i -> {
            assertTrue("The socket has not been closed for an unknown alert with level fatal", Validator.socketClosed(i));
        });
    }
    
    private void peformUnknownWarningAlertTest(WorkflowTrace trace, WorkflowRunner runner, Config config) {
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit((byte)200));
        trace.addTlsAction(new SendAction(alert));
        
        runner.execute(trace, config).validateFinal(i -> {
            assertTrue("The socket has not been closed for an unknown alert with level warning", Validator.socketClosed(i));
        });
    }
    
    public boolean isMeantToBeFatalLevel(AlertDescription alert) {
        return alert != AlertDescription.CLOSE_NOTIFY && alert != AlertDescription.DECRYPTION_FAILED_RESERVED && alert != AlertDescription.DECOMPRESSION_FAILURE && alert != AlertDescription.NO_CERTIFICATE_RESERVED && alert != AlertDescription.EXPORT_RESTRICTION_RESERVED && alert != AlertDescription.USER_CANCELED && alert != AlertDescription.NO_RENEGOTIATION && alert != AlertDescription.CERTIFICATE_UNOBTAINABLE && alert != AlertDescription.BAD_CERTIFICATE_HASH_VALUE && alert.getValue() <= 120;
    }
    
    private void performFatalAlertWithWarningLevelTest(WorkflowTrace trace, WorkflowRunner runner, Config config) {
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue().getValue()));
        trace.addTlsAction(new SendAction(alert));
        
        runner.execute(trace, config).validateFinal(i -> {
            assertTrue("The socket has not been closed for a fatal alert with level warning", Validator.socketClosed(i));
        });
    }
}
