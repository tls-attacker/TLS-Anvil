/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.anvil;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import jakarta.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

public class TlsTestCase extends AnvilTestCase {
    private static final Logger LOGGER = LogManager.getLogger();
    private State state;

    private TlsTestCase() {}

    public TlsTestCase(
            ExtensionContext context, State state, TlsParameterCombination parameterCombination) {
        super(parameterCombination, context);
        this.state = state;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public void validateFinal(Consumer<TlsTestCase> validateFunction) {
        // Todo: move to WorkflowRunner?
        try {
            validateFunction.accept(this);
            if (getTestResult() == TestResult.NOT_SPECIFIED) {
                setTestResult(TestResult.STRICTLY_SUCCEEDED);
            }
        } catch (Throwable err) {
            if (state.getExecutionException() != null) {
                err.addSuppressed(state.getExecutionException());
            }

            if (state.getTlsContext().isReceivedTransportHandlerException()) {
                addAdditionalResultInfo("Received TransportHandler exception");
            }

            setFailedReason(err);
            throw err;
        }
    }

    @JsonProperty("Stacktrace")
    public String getStacktrace() {
        if (getFailedReason() != null) {
            return ExecptionPrinter.stacktraceToString(getFailedReason());
        }
        return null;
    }

    public WorkflowTrace getWorkflowTrace() {
        if (state != null) {
            return state.getWorkflowTrace();
        }
        return null;
    }

    @JsonProperty("uuid")
    public String getUuid() {
        StringBuilder toHash = new StringBuilder();
        toHash.append(this.getAdditionalTestInformation());
        if (getParameterCombination() != null) {
            toHash.append(this.getParameterCombination().toString());
        }
        toHash.append(getAssociatedContainer().getTestClass().getName());
        toHash.append(getAssociatedContainer().getTestMethod().getName());

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(toHash.toString().getBytes(StandardCharsets.UTF_8));
            return DatatypeConverter.printHexBinary(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not possible...");
        }
    }

    @JsonProperty("StartTimestamp")
    public String getStartTimestamp() {
        if (state == null) return null;
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(state.getStartTimestamp()));
    }

    @JsonProperty("EndTimestamp")
    public String getEndTimestamp() {
        if (state == null) return null;
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(state.getEndTimestamp()));
    }

    @JsonProperty("SrcPort")
    public Integer getSrcPort() {
        if (state == null) return null;
        else if (state.getTlsContext().getTransportHandler() instanceof TcpTransportHandler) {
            return ((TcpTransportHandler) state.getTlsContext().getTransportHandler()).getSrcPort();
        } else if (state.getTlsContext().getTransportHandler() instanceof UdpTransportHandler) {
            return ((UdpTransportHandler) state.getTlsContext().getTransportHandler()).getSrcPort();
        } else {
            throw new NotImplementedException(
                    "The transport protocol used is not yet implemented.");
        }
    }

    @JsonProperty("DstPort")
    public Integer getDstPort() {
        if (state == null) return null;
        else if (state.getTlsContext().getTransportHandler() instanceof TcpTransportHandler) {
            return ((TcpTransportHandler) state.getTlsContext().getTransportHandler()).getDstPort();
        } else if (state.getTlsContext().getTransportHandler() instanceof UdpTransportHandler) {
            return ((UdpTransportHandler) state.getTlsContext().getTransportHandler()).getDstPort();
        } else {
            throw new NotImplementedException(
                    "The transport protocol used is not yet implemented.");
        }
    }
}
