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
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.exceptions.TransportHandlerExpection;
import de.rub.nds.tlstest.framework.reporting.ScoreContainer;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;


/**
 * Usually each test case performing a handshake is associated with a AnnotatedStateContainer.
 * This class contains a list of States / Handshakes that are the result
 * of the derication process.
 */
@XmlAccessorType(XmlAccessType.NONE)
public class  AnnotatedStateContainer {
    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "TestMethod")
    @JsonProperty("TestMethod")
    private TestMethodConfig testMethodConfig;

    private int statusRaw = 0;

    @XmlElement(name = "DisabledReason")
    @JsonProperty("DisabledReason")
    private String disabledReason;

    private Throwable failedStacktrace;

    @XmlElement(name = "FailedReason")
    @JsonProperty("FailedReason")
    private String failedReason;

    @XmlElement(name = "ElapsedTime")
    @JsonProperty("ElapsedTime")
    private long elapsedTime = 0;

    @XmlElementWrapper(name = "States")
    @XmlElement(name = "State")
    @JsonProperty("States")
    private List<AnnotatedState> states = new ArrayList<>();

    @JsonUnwrapped
    private ScoreContainer scoreContainer;

    private String uniqueId;

    public AnnotatedStateContainer() { }

    public AnnotatedStateContainer(ExtensionContext extensionContext, List<AnnotatedState> states) {
        updateExtensionContext(extensionContext);
        this.addAll(states);
    }

    public AnnotatedStateContainer(ExtensionContext extensionContext, AnnotatedState... states) {
        this(extensionContext, Arrays.asList(states));
    }


    public void addAll(@Nonnull AnnotatedStateContainer container) {
        List<AnnotatedState> states = container.getStates();
        states.parallelStream().forEach(i -> i.setAssociatedContainer(this));
        this.states.addAll(states);
    }

    public void addAll(List<AnnotatedState> states) {
        states.parallelStream().forEach(i -> i.setAssociatedContainer(this));
        this.states.addAll(states);
    }

    public void addAll(AnnotatedState... states) {
        this.addAll(Arrays.asList(states));
    }

    public void add(AnnotatedState state) {
        state.setAssociatedContainer(this);
        this.states.add(state);
    }

    /**
     * Used by the test cases to validate the received messages.
     * Iterates over the list of states and executes the lambda function for every state.
     *
     *
     * @param finalValidation if set to true, an execption is thrown when the validation fails for one state
     * @param f lambda function that accepts a annotated state
     */
    public void validate(boolean finalValidation, Consumer<AnnotatedState> f) {
        boolean failed = false;
        List<Throwable> errors = new ArrayList<>();

        for (AnnotatedState i : states) {
            try {
                f.accept(i);
                if (i.getStatus() == TestStatus.NOT_SPECIFIED) {
                    i.setStatus(TestStatus.SUCCEEDED);
                    stateFinished(TestStatus.SUCCEEDED);
                }
                else {
                    stateFinished(i.getStatus());
                }
            } catch (Throwable err) {
                failed = true;

                if (i.getState().getExecutionException() != null) {
                    err.addSuppressed(i.getState().getExecutionException());
                }

                Throwable error = err;
                if (i.getState().getTlsContext().isReceivedTransportHandlerException()) {
                    error = new TransportHandlerExpection("Received transportHandler excpetion", err);
                }

                i.setFailedReason(error);
                errors.add(error);
                stateFinished(TestStatus.FAILED);
            }
        }

        if (finalValidation) {
            TestContext.getInstance().addTestResult(this);
            List<String> uuids = new ArrayList<>();
            for (AnnotatedState state : this.getStates()) {
                if (uuids.contains(state.getUuid())) {
                    LOGGER.warn("uuids of states in container are not unique! ({}.{})", this.testMethodConfig.getClassName(), this.testMethodConfig.getMethodName());
                    break;
                }
                uuids.add(state.getUuid());
            }

            if (failed) {
                for (Throwable i: errors) {
                    if (System.getenv("DOCKER") != null) {
                        LOGGER.debug("", i);
                    } else {
                        LOGGER.error("", i);
                    }
                }
                AssertionError error = new AssertionError(String.format("%d/%d tests failed", errors.size(), states.size()));
                this.setFailedStacktrace(error);
                throw error;
            }
        }
    }

    private void stateFinished(TestStatus stateStatus) {
        setStatusRaw(this.statusRaw | stateStatus.getValue());
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

    public void setStatusRaw(int statusRaw) {
        this.statusRaw = statusRaw;
        scoreContainer.updateForStatus(getStatus());
    }

    @XmlElement(name = "Status")
    @JsonProperty("Status")
    public TestStatus getStatus() {
        return TestStatus.statusForBitmask(statusRaw);
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

    public Long getElapsedTime() {
        return elapsedTime;
    }

    public void setElapsedTime(Long elapsedTime) {
        this.elapsedTime = elapsedTime;
    }

    public void updateExtensionContext(ExtensionContext extensionContext) {
        this.uniqueId = extensionContext.getUniqueId();
        this.testMethodConfig = new TestMethodConfig(extensionContext);
        if (this.scoreContainer == null) {
            this.scoreContainer = new ScoreContainer(extensionContext);
        }
    }

    public ScoreContainer getScoreContainer() {
        return scoreContainer;
    }
}
