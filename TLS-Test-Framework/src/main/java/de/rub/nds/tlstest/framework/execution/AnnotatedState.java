package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;

import javax.annotation.Nonnull;

public class AnnotatedState {

    private State state;
    private String transformDescription = "";

    private TestMethodConfig testMethodConfig;

    private Throwable failedReason;
    private TestStatus status;

    AnnotatedState(@Nonnull State state, TestMethodConfig config) {
        this.state = state;
        this.testMethodConfig = config;
        this.status = TestStatus.NOT_SPECIFIED;

        if (state.getFinishedFuture().isDone()) {
            this.status = TestStatus.SUCCEEDED;
        }
        else if (state.getFinishedFuture().isCancelled() || state.getFinishedFuture().isCompletedExceptionally()) {
            this.status = TestStatus.FAILED;
        }
    }

    AnnotatedState(AnnotatedState aState, State mutated) {
        this.testMethodConfig = aState.testMethodConfig;
        this.status = aState.status;
        this.state = mutated;
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

    public TestMethodConfig getTestMethodConfig() {
        return testMethodConfig;
    }

    public void setTestMethodConfig(TestMethodConfig testMethodConfig) {
        this.testMethodConfig = testMethodConfig;
    }

    public Throwable getFailedReason() {
        return failedReason;
    }

    public void setFailedReason(Throwable failedReason) {
        this.failedReason = failedReason;
    }
}
