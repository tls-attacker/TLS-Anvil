/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.function.Consumer;

public class AnnotatedState {
    private static final Logger LOGGER = LogManager.getLogger();
    private State state;

    private Throwable failedReason;
    private AnnotatedStateContainer associatedContainer;

    @JsonProperty("Result")
    private TestResult result = TestResult.NOT_SPECIFIED;

    @JsonProperty("DisplayName")
    private String displayName;

    @JsonProperty("DerivationContainer")
    private DerivationContainer derivationContainer;

    private List<String> additionalResultInformation = null;
    private List<String> additionalTestInformation = null;

    private ExtensionContext extensionContext;

    private AnnotatedState() {}

    public AnnotatedState(ExtensionContext context, State state, DerivationContainer container) {
        this.state = state;
        this.extensionContext = context;
        this.displayName = context.getDisplayName();
        this.associatedContainer = AnnotatedStateContainer.forExtensionContext(context);
        this.associatedContainer.add(this);
        this.derivationContainer = container;
    }


    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }


    public TestResult getResult() {
        return result;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public Throwable getFailedReason() {
        return failedReason;
    }

    public void setFailedReason(Throwable failedReason) {
        this.failedReason = failedReason;
        this.result = this.failedReason != null ? TestResult.FAILED : TestResult.NOT_SPECIFIED;
    }

    public void validateFinal(Consumer<AnnotatedState> validateFunction) {
        try {
            validateFunction.accept(this);
            if (result == TestResult.NOT_SPECIFIED) {
                result = TestResult.SUCCEEDED;
            }
        } catch (Throwable err) {
            if (state.getExecutionException() != null) {
                err.addSuppressed(state.getExecutionException());
            }

            if (state.getTlsContext().isReceivedTransportHandlerException()) {
                this.addAdditionalResultInfo("Received TransportHandler exception");
            }

            setFailedReason(err);
            associatedContainer.stateFinished(result);
            throw err;
        }
        
        associatedContainer.stateFinished(result);
    }

    @JsonProperty("Stacktrace")
    public String getStacktrace() {
        if (failedReason != null) {
            return ExecptionPrinter.stacktraceToString(failedReason);
        }
        return null;
    }

    public WorkflowTrace getWorkflowTrace() {
        if (state != null) {
            return state.getWorkflowTrace();
        }
        return null;
    }

    @JsonProperty("AdditionalResultInformation")
    public String getAdditionalResultInformation() {
        if (additionalResultInformation == null) return "";
        return String.join(";\n", additionalResultInformation);
    }

    public void addAdditionalResultInfo(String info) {
        if (additionalResultInformation == null) {
            additionalResultInformation = new ArrayList<>();
        }

        additionalResultInformation.add(info);
    }

    @JsonProperty("AdditionalTestInformation")
    public String getAdditionalTestInformation() {
        if (additionalTestInformation == null) return "";
        return String.join(";\n", additionalTestInformation);
    }

    public void addAdditionalTestInfo(String info) {
        if (additionalTestInformation == null) {
            additionalTestInformation = new ArrayList<>();
        }

        additionalTestInformation.add(info);
    }

    @JsonProperty("uuid")
    public String getUuid() {
        StringBuilder toHash = new StringBuilder();
        toHash.append(this.getAdditionalTestInformation());
        if (this.derivationContainer != null) {
            toHash.append(this.derivationContainer.toString());
        }
        toHash.append(associatedContainer.getTestMethodConfig().getClassName());
        toHash.append(associatedContainer.getTestMethodConfig().getMethodName());

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
        return ((TcpTransportHandler)state.getTlsContext().getTransportHandler()).getSrcPort();
    }

    @JsonProperty("DstPort")
    public Integer getDstPort() {
        if (state == null) return null;
        return ((TcpTransportHandler)state.getTlsContext().getTransportHandler()).getDstPort();
    }


    public AnnotatedStateContainer getAssociatedContainer() {
        return associatedContainer;
    }

    public void setAssociatedContainer(AnnotatedStateContainer associatedContainer) {
        this.associatedContainer = associatedContainer;
    }

    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }

    public DerivationContainer getDerivationContainer() {
        return derivationContainer;
    }
}
