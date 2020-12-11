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

    public void finished() {
        TestContext.getInstance().testFinished();
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
            if(anyStateSucceeded()) {
                String tmp = failureInducingCombinations.stream().map(DerivationContainer::toString).collect(Collectors.joining("\n\t"));
                LOGGER.info("The following parameters resulted in test failures for test " + testMethodConfig.getMethodName() + ":\n\t{}", tmp);
            } else {
                LOGGER.info("All generated inputs resulted in failures for test " + testMethodConfig.getMethodName());
            }
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
    
    private boolean anyStateSucceeded() {
        return states.stream().anyMatch(state -> state.getResult() == TestResult.SUCCEEDED);
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
