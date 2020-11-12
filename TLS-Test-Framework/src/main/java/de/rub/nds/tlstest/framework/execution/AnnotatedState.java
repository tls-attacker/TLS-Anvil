/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.exceptions.TransportHandlerExpection;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.function.Consumer;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class AnnotatedState {
    private static final Logger LOGGER = LogManager.getLogger();
    private State state;

    private List<String> transformationDescription = null;

    private Throwable failedReason;
    private AnnotatedStateContainer associatedContainer;

    @XmlElement(name = "Result")
    @JsonProperty("Result")
    private TestResult result = TestResult.NOT_SPECIFIED;

    @XmlElement(name = "InspectedCiphersuite")
    @JsonProperty("InspectedCiphersuite")
    private CipherSuite inspectedCipherSuite;

    private String parentUUID;

    private List<String> additionalResultInformation = null;
    private List<String> additionalTestInformation = null;
    
    private boolean omitFromTests = false;

    public AnnotatedState() {}

    public AnnotatedState(@Nonnull State state) {
        this.state = state;
    }

    AnnotatedState(AnnotatedState aState, State mutated) {
        this.state = mutated;
        this.inspectedCipherSuite = aState.inspectedCipherSuite;

        if (aState.additionalTestInformation != null)
            this.additionalTestInformation = new ArrayList<>(aState.additionalTestInformation);

        if (aState.additionalResultInformation != null)
            this.additionalResultInformation = new ArrayList<>(aState.additionalResultInformation);
    }

    AnnotatedState(AnnotatedState aState) {
        this(aState, null);

        WorkflowTrace trace = aState.getState().getWorkflowTraceCopy();
        Config config = aState.getState().getConfig().createCopy();
        this.omitFromTests = aState.omitFromTests;
        this.setState(new State(config, trace));
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

    public CipherSuite getInspectedCipherSuite() {
        return inspectedCipherSuite;
    }

    public void setInspectedCipherSuite(CipherSuite inspectedCipherSuite) {
        this.inspectedCipherSuite = inspectedCipherSuite;
    }

    @XmlElement(name = "Stacktrace")
    @JsonProperty("Stacktrace")
    public String getStacktrace() {
        if (failedReason != null) {
            return ExecptionPrinter.stacktraceToString(failedReason);
        }
        return null;
    }

    @XmlElement(name = "WorkflowTrace")
    public WorkflowTrace getWorkflowTrace() {
        if (state != null) {
            return state.getWorkflowTrace();
        }
        return null;
    }

//    @JsonProperty("WorkflowTrace")
    public String getSerializedWorkflowTrace() {
        try {
            return WorkflowTraceSerializer.write(state.getWorkflowTrace());
        }
        catch (Exception e) {
            LOGGER.error("Could not serialize WorkflowTrace");
            return null;
        }

    }

    @XmlElement(name = "AdditionalResultInformation")
    @JsonProperty("AdditionalResultInformation")
    public String getAdditionalResultInformation() {
        if (additionalResultInformation == null) return "";
        return String.join("\n", additionalResultInformation);
    }

    public void addAdditionalResultInfo(String info) {
        if (additionalResultInformation == null) {
            additionalResultInformation = new ArrayList<>();
        }

        additionalResultInformation.add(info);
    }

    @XmlElement(name = "AdditionalTestInformation")
    @JsonProperty("AdditionalTestInformation")
    public String getAdditionalTestInformation() {
        if (additionalTestInformation == null) return "";
        return String.join("\n", additionalTestInformation);
    }

    public void addAdditionalTestInfo(String info) {
        if (additionalTestInformation == null) {
            additionalTestInformation = new ArrayList<>();
        }

        additionalTestInformation.add(info);
    }

    @XmlElement(name = "TransformationDescription")
    @JsonProperty("TransformationDescription")
    public String getTransformationDescription() {
        if (transformationDescription == null) return "";
        return String.join(", ", transformationDescription);
    }

    public void addTransformationDescription(String info) {
        if (transformationDescription == null) {
            transformationDescription = new ArrayList<>();
        }

        transformationDescription.add(info);
    }

    @XmlElement(name = "uuid")
    @JsonProperty("uuid")
    public String getUuid() {
        StringBuilder toHash = new StringBuilder();
        if (this.getInspectedCipherSuite() != null)
            toHash.append(this.getInspectedCipherSuite().toString());
        toHash.append(this.getTransformationDescription());
        toHash.append(this.getAdditionalTestInformation());
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

    @XmlElement(name = "TransformationParentUuid")
    @JsonProperty("TransformationParentUuid")
    public String getParentUUID() {
        return parentUUID;
    }

    public void setParentUUID(String parentUUID) {
        this.parentUUID = parentUUID;
    }

    @JsonProperty("StartTimestamp")
    public String getStartTimestamp() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(state.getStartTimestamp()));
    }

    @JsonProperty("EndTimestamp")
    public String getEndTimestamp() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(state.getEndTimestamp()));
    }

    @JsonProperty("SrcPort")
    public int getSrcPort() {
        return ((TcpTransportHandler)state.getTlsContext().getTransportHandler()).getSrcPort();
    }

    @JsonProperty("DstPort")
    public int getDstPort() {
        return ((TcpTransportHandler)state.getTlsContext().getTransportHandler()).getDstPort();
    }


    public AnnotatedStateContainer getAssociatedContainer() {
        return associatedContainer;
    }

    public void setAssociatedContainer(AnnotatedStateContainer associatedContainer) {
        this.associatedContainer = associatedContainer;
    }

    public boolean isOmitFromTests() {
        return omitFromTests;
    }

    public void setOmitFromTests(boolean omitFromTests) {
        this.omitFromTests = omitFromTests;
    }
}
