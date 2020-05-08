package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;

import javax.annotation.Nonnull;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class AnnotatedState {

    private State state;

    @XmlElement(name = "TransformationDescription")
    private String transformDescription = null;

    private Throwable failedReason;

    @XmlElement(name = "Status")
    private TestStatus status;

    @XmlElement(name = "InspectedCiphersuite")
    private CipherSuite inspectedCipherSuite;

    public AnnotatedState() {}

    AnnotatedState(@Nonnull State state) {
        this.state = state;
        this.status = TestStatus.NOT_SPECIFIED;

        if (state.getFinishedFuture().isDone()) {
            this.status = TestStatus.SUCCEEDED;
        }
        else if (state.getFinishedFuture().isCancelled() || state.getFinishedFuture().isCompletedExceptionally()) {
            this.status = TestStatus.FAILED;
        }
    }

    AnnotatedState(AnnotatedState aState, State mutated) {
        this.status = TestStatus.NOT_SPECIFIED;
        this.state = mutated;
        this.inspectedCipherSuite = aState.inspectedCipherSuite;
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

    public String getTransformDescription() {
        return transformDescription;
    }

    public void setTransformDescription(String transformDescription) {
        this.transformDescription = transformDescription;
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

}
