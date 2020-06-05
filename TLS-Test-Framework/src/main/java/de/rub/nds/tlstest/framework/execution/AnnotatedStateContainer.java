package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.exceptions.TransportHandlerExpection;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;


@XmlAccessorType(XmlAccessType.NONE)
public class  AnnotatedStateContainer {
    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "TestMethod")
    @JsonProperty("TestMethod")
    private TestMethodConfig testMethodConfig;

    @XmlElement(name = "Status")
    @JsonProperty("Status")
    private TestStatus status = TestStatus.NOT_SPECIFIED;

    @XmlElement(name = "DisabledReason")
    @JsonProperty("DisabledReason")
    private String disabledReason;

    private Throwable failedStacktrace;

    @XmlElement(name = "FailedReason")
    @JsonProperty("FailedReason")
    private String failedReason;

    @XmlElementWrapper(name = "States")
    @XmlElement(name = "State")
    @JsonProperty("States")
    private List<AnnotatedState> states = new ArrayList<>();

    private String uniqueId;

    AnnotatedStateContainer(String uniqueId, TestMethodConfig tmc, List<AnnotatedState> states) {
        this.states = states;
        this.uniqueId = uniqueId;
        this.testMethodConfig = tmc;
    }

    public AnnotatedStateContainer() { }

    AnnotatedStateContainer(String uniqueId, TestMethodConfig tmc, AnnotatedState... states) {
        this(uniqueId, tmc, Arrays.asList(states));
    }


    public void addAll(@Nonnull AnnotatedStateContainer container) {
        this.states.addAll(container.getStates());
    }

    public void addAll(List<AnnotatedState> states) {
        this.states.addAll(states);
    }

    public void addAll(AnnotatedState... states) {
        this.states.addAll(Arrays.asList(states));
    }

    public void add(AnnotatedState state) {
        this.states.add(state);
    }

    public void validate(boolean finalValidation, Consumer<AnnotatedState> f) {
        boolean failed = false;
        List<Throwable> errors = new ArrayList<>();

        for (AnnotatedState i : states) {
            State state = i.getState();
            try {
                state.getFinishedFuture().get(0, TimeUnit.MILLISECONDS);
                if (i.getState().getTlsContext().isReceivedTransportHandlerException()) {
                    throw new TransportHandlerExpection("Received transportHandler excpetion");
                }
                f.accept(i);
                if (i.getStatus() == TestStatus.NOT_SPECIFIED) {
                    i.setStatus(TestStatus.SUCCEEDED);
                    stateFinished(TestStatus.SUCCEEDED);
                }
                else {
                    stateFinished(i.getStatus());
                }
            } catch (Throwable error) {
                failed = true;
                i.setFailedReason(error);
                errors.add(error);
                stateFinished(TestStatus.FAILED);
            }
        }

        if (finalValidation) {
            TestContext.getInstance().addTestResult(this);
            if (failed) {
                for (Throwable i: errors) {
                    LOGGER.error("\n" + ExecptionPrinter.stacktraceToString(i));
                }
                AssertionError error = new AssertionError(String.format("%d/%d tests failed", errors.size(), states.size()));
                this.setFailedStacktrace(error);
                throw error;
            }
        }
    }

    private void stateFinished(TestStatus stateStatus) {
        if (status == TestStatus.NOT_SPECIFIED) {
            this.status = stateStatus;
        }
        else if ((status == TestStatus.FAILED && stateStatus == TestStatus.SUCCEEDED) ||
                (status == TestStatus.SUCCEEDED && stateStatus == TestStatus.FAILED)) {
            status = TestStatus.PARTIALLY_FAILED;
        }
    }

    public void validateFinal(Consumer<AnnotatedState> f) {
        this.validate(true, f);
    }

    public void validate(Consumer<AnnotatedState> f) {
        this.validate(false, f);
    }

    public List<AnnotatedState> getStates() {
        return states;
    }

    public void setStates(List<AnnotatedState> states) {
        this.states = states;
    }

    public String getUniqueId() {
        return uniqueId;
    }

    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public TestStatus getStatus() {
        return status;
    }

    public void setStatus(TestStatus status) {
        this.status = status;
    }

    public TestMethodConfig getTestMethodConfig() {
        return testMethodConfig;
    }

    public void setTestMethodConfig(TestMethodConfig testMethodConfig) {
        this.testMethodConfig = testMethodConfig;
    }

    public String getDisabledReason() {
        return disabledReason;
    }

    public void setDisabledReason(String disabledReason) {
        this.disabledReason = disabledReason;
    }

    public Throwable getFailedStacktrace() {
        return failedStacktrace;
    }

    public void setFailedStacktrace(Throwable failedStacktrace) {
        this.failedReason = failedStacktrace.getMessage();
        this.failedStacktrace = failedStacktrace;
    }

    @XmlElement(name = "FailedStacktrace")
    @JsonProperty("FailedStacktrace")
    public String getStacktrace() {
        if (failedStacktrace != null) {
            return ExecptionPrinter.stacktraceToString(failedStacktrace);
        }
        return null;
    }

    public String getFailedReason() {
        return failedReason;
    }

    public void setFailedReason(String failedReason) {
        this.failedReason = failedReason;
    }
}
