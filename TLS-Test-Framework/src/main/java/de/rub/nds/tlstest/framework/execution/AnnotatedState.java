package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class AnnotatedState {
    private static final Logger LOGGER = LogManager.getLogger();
    private State state;

    private List<String> transformationDescription = null;

    private Throwable failedReason;

    @XmlElement(name = "Status")
    @JsonProperty("Status")
    private TestStatus status = TestStatus.NOT_SPECIFIED;

    @XmlElement(name = "InspectedCiphersuite")
    @JsonProperty("InspectedCiphersuite")
    private CipherSuite inspectedCipherSuite;

    private UUID uuid = UUID.randomUUID();
    private UUID parentUUID;


    private List<String> additionalResultInformation = null;
    private List<String> additionalTestInformation = null;

    public AnnotatedState() {}

    public AnnotatedState(@Nonnull State state) {
        this.state = state;

        if (state.getFinishedFuture().isDone()) {
            this.status = TestStatus.SUCCEEDED;
        }
        else if (state.getFinishedFuture().isCancelled() || state.getFinishedFuture().isCompletedExceptionally()) {
            this.status = TestStatus.FAILED;
        }
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
        this.setState(new State(config, trace));
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }


    public TestStatus getStatus() {
        return status;
    }

    public void setStatus(TestStatus status) {
        this.status = status;
    }

    public Throwable getFailedReason() {
        return failedReason;
    }

    public void setFailedReason(Throwable failedReason) {
        this.failedReason = failedReason;
        this.status = this.failedReason != null ? TestStatus.FAILED : TestStatus.NOT_SPECIFIED;
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

    @JsonProperty("WorkflowTrace")
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
    public String getStringUuid() {
        return uuid.toString();
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    @XmlElement(name = "TransformationParentUuid")
    @JsonProperty("TransformationParentUuid")
    public UUID getParentUUID() {
        return parentUUID;
    }

    public void setParentUUID(UUID parentUUID) {
        this.parentUUID = parentUUID;
    }
}
