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
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.reporting.ScoreContainer;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import de.rub.nds.tlstest.framework.utils.Utils;
import de.rwth.swc.coffee4j.model.Combination;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;


/**
 * Usually each test case performing a handshake is associated with a AnnotatedStateContainer.
 * This class contains a list of States / Handshakes that are the result
 * of the derication process.
 */
@XmlAccessorType(XmlAccessType.NONE)
public class  AnnotatedStateContainer {
    private static final Logger LOGGER = LogManager.getLogger();
    private boolean finished = false;

    @XmlElement(name = "TestMethod")
    @JsonProperty("TestMethod")
    private TestMethodConfig testMethodConfig;

    private int resultRaw = 0;

    @XmlElement(name = "DisabledReason")
    @JsonProperty("DisabledReason")
    private String disabledReason;

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

    @JsonProperty("FailureInducingCombinations")
    List<DerivationContainer> failureInducingCombinations;

    @Deprecated
    public AnnotatedStateContainer() { }

    @Deprecated
    public AnnotatedStateContainer(ExtensionContext extensionContext, List<AnnotatedState> states) {
        this.addAll(states);
    }

    @Deprecated
    public AnnotatedStateContainer(ExtensionContext extensionContext, AnnotatedState... states) {
        this(extensionContext, Arrays.asList(states));
    }

    private AnnotatedStateContainer(ExtensionContext extensionContext) {
        this.uniqueId = extensionContext.getUniqueId();
        this.scoreContainer = new ScoreContainer(extensionContext);
    }

    synchronized public static AnnotatedStateContainer forExtensionContext(ExtensionContext extensionContext) {
        ExtensionContext resolvedContext = Utils.getTemplateContainerExtensionContext(extensionContext);

        if (TestContext.getInstance().getTestResult(resolvedContext.getUniqueId()) != null) {
            return TestContext.getInstance().getTestResult(resolvedContext.getUniqueId());
        }

        AnnotatedStateContainer container = new AnnotatedStateContainer(resolvedContext);
        container.setTestMethodConfig(new TestMethodConfig(resolvedContext));
        TestContext.getInstance().addTestResult(container);
        return container;
    }

    @Deprecated
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
    @Deprecated
    public void validate(boolean finalValidation, Consumer<AnnotatedState> f) {

    }

    @Deprecated
    public void validateFinal(Consumer<AnnotatedState> f) {
        this.validate(true, f);
    }

    @Deprecated
    public void validate(Consumer<AnnotatedState> f) {
        this.validate(false, f);
    }

    public void finished() {
        finished = true;
        List<String> uuids = new ArrayList<>();
        List<Throwable> errors = new ArrayList<>();
        boolean failed = false;
        for (AnnotatedState state : this.getStates()) {
            if (state.getResult() == TestResult.FAILED) {
                errors.add(state.getFailedReason());
                failed = true;
            }

            if (uuids.contains(state.getUuid())) {
                LOGGER.warn("uuids of states in container are not unique! ({}.{})", this.testMethodConfig.getClassName(), this.testMethodConfig.getMethodName());
                continue;
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
            failedReason = String.format("%d/%d tests failed", errors.size(), states.size());
        }

        if (failureInducingCombinations != null) {
            String tmp = failureInducingCombinations.stream().map(DerivationContainer::toString).collect(Collectors.joining("\n\t"));
            LOGGER.info("The following parameters resulted in test failures:\n\t{}", tmp);
        }
    }

    public void stateFinished(TestResult result) {
        setResultRaw(this.resultRaw | result.getValue());
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

    public void setResultRaw(int resultRaw) {
        this.resultRaw = resultRaw;
        scoreContainer.updateForResult(getResult());
    }

    @XmlElement(name = "Result")
    @JsonProperty("Result")
    public TestResult getResult() {
        return TestResult.resultForBitmask(resultRaw);
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

    public Long getElapsedTime() {
        return elapsedTime;
    }

    public void setElapsedTime(Long elapsedTime) {
        this.elapsedTime = elapsedTime;
    }

    public List<DerivationContainer> getFailureInducingCombinations() {
        return failureInducingCombinations;
    }

    public void setFailureInducingCombinations(List<Combination> failureInducingCombinations) {
        if (failureInducingCombinations == null || failureInducingCombinations.isEmpty())
            return;

        List<DerivationContainer> parameters = new ArrayList<>();
        for (Combination i : failureInducingCombinations) {
            DerivationContainer container = DerivationContainer.fromCombination(i);
            parameters.add(container);
        }

        this.failureInducingCombinations = parameters;
    }

    public ScoreContainer getScoreContainer() {
        return scoreContainer;
    }

    public String getFailedReason() {
        return failedReason;
    }

    public void setFailedReason(String failedReason) {
        this.failedReason = failedReason;
    }

    public boolean isFinished() {
        return finished;
    }
}
