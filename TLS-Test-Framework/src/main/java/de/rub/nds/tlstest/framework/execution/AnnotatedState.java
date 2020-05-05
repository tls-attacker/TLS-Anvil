package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.constants.TestStatus;

import javax.annotation.Nonnull;

public class AnnotatedState {

    private State state;
    private String transformDescription = "";
    private String testDescription;
    private String testMethod;
    private Throwable failedReason;
    private TestStatus status;

    AnnotatedState(@Nonnull State state, String testDescription, String testMethod) {
        this.state = state;
        this.testDescription = testDescription;
        this.testMethod = testMethod;
        this.status = TestStatus.NOT_SPECIFIED;

        if (state.getFinishedFuture().isDone()) {
            this.status = TestStatus.SUCCEEDED;
        }
        else if (state.getFinishedFuture().isCancelled() || state.getFinishedFuture().isCompletedExceptionally()) {
            this.status = TestStatus.FAILED;
        }
    }

    AnnotatedState(AnnotatedState aState, State mutated) {
        this.testDescription = aState.testDescription;
        this.testMethod = aState.testMethod;
        this.status = aState.status;
        this.state = mutated;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public String getTestDescription() {
        return testDescription;
    }

    public void setTestDescription(String testDescription) {
        this.testDescription = testDescription;
    }

    public String getTestMethod() {
        return testMethod;
    }

    public void setTestMethod(String testMethod) {
        this.testMethod = testMethod;
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
    }
}
