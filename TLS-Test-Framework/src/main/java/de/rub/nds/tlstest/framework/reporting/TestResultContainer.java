/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.rub.nds.tlstest.framework.constants.TestCategory;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import org.junit.platform.launcher.TestIdentifier;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@XmlRootElement(name = "TestResultReport")
@XmlAccessorType(XmlAccessType.NONE)
public class TestResultContainer {
    @XmlElement(name = "DisplayName")
    @JsonProperty("DisplayName")
    private String displayName;

    private Map<String, AnnotatedStateContainer> results = new HashMap<>();
    private Map<String, TestResultContainer> children = new HashMap<>();

    private String uniqueId;

    @XmlElement(name = "TestEndpointMode")
    @JsonProperty("TestEndpointMode")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private TestEndpointType testEndpointType = null;

    @XmlElement(name = "Identifier")
    @JsonProperty("Identifier")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String identifier = null;

    @XmlElement(name = "Date")
    @JsonProperty("Date")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Date date = null;

    @XmlElement(name = "ElapsedTime")
    @JsonProperty("ElapsedTime")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Long elapsedTime = null;

    @XmlElement(name = "FailedTests")
    @JsonProperty("FailedTests")
    private long testsFailed = 0;

    @XmlElement(name = "SucceededTests")
    @JsonProperty("SucceededTests")
    private long testsSucceeded = 0;

    @XmlElement(name = "DisabledTests")
    @JsonProperty("DisabledTests")
    private long testsDisabled = 0;


    @JsonUnwrapped
    private ScoreContainer scoreContainer = ScoreContainer.forEveryCategory();

    private TestResultContainer parent = null;


    public TestResultContainer(TestIdentifier identifier) {
        this.uniqueId = identifier.getUniqueId();
        this.displayName = identifier.getDisplayName();
    }

    public TestResultContainer() {
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public Map<String, AnnotatedStateContainer> getResults() {
        return this.results;
    }

    public void setResults(Map<String, AnnotatedStateContainer> results) {
        this.results = results;
    }

    public void addResult(AnnotatedStateContainer result) {
        this.results.put(result.getUniqueId(), result);
    }

    public Long getElapsedTime() {
        return elapsedTime;
    }

    public void setElapsedTime(Long elapsedTime) {
        this.elapsedTime = elapsedTime;
    }

    public void addResultWithParent(String parentId, AnnotatedStateContainer result) {
        TestResultContainer container = this.getContainerWithId(parentId);
        container.addResult(result);

        while (container != null) {
            container.updateTestStats(result);
            container = container.parent;
        }
    }

    public Map<String, TestResultContainer> getChildren() {
        return children;
    }

    public void setChildren(Map<String, TestResultContainer> children) {
        this.children = children;
    }

    public TestResultContainer addChildContainer(TestIdentifier container) {
        if (!container.getParentId().isPresent()) {
            throw new RuntimeException("Could not add child container");
        }
        String parentId = container.getParentId().get();
        if (parentId.equals(uniqueId)) {
            TestResultContainer c = new TestResultContainer(container);
            c.parent = this;
            this.children.put(container.getUniqueId(), c);
            return c;
        }

        TestResultContainer parentContainer = getContainerWithId(parentId);
        if (parentContainer == null) {
            throw new RuntimeException("Could not add child container");
        }

        return parentContainer.addChildContainer(container);
    }

    public String getUniqueId() {
        return uniqueId;
    }

    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public TestResultContainer getContainerWithId(String uniqueId) {
        if (children.get(uniqueId) != null) {
            return children.get(uniqueId);
        }
        if (children.size() > 0) {
            for (TestResultContainer i : children.values()) {
                if (i.getContainerWithId(uniqueId) != null) {
                    return i.getContainerWithId(uniqueId);
                }
            }
        }
        return null;
    }


    @XmlElement(name = "TestResult")
    @JsonProperty("TestResults")
    public List<AnnotatedStateContainer> getResultsList() {
        if (results.size() > 0) {
            return new ArrayList<>(results.values());
        }
        return null;
    }

    @XmlElement(name = "TestClass")
    @JsonProperty("TestClasses")
    public List<TestResultContainer> getChildrenList() {
        if (children.size() > 0) {
            return new ArrayList<>(children.values());
        }
        return null;
    }

    private void updateTestStats(AnnotatedStateContainer result) {
        switch (result.getResult()) {
            case PARTIALLY_FAILED:
            case FAILED:
                this.testsFailed++;
                break;
            case PARTIALLY_SUCCEEDED:
            case SUCCEEDED:
                this.testsSucceeded++;
                break;
            case DISABLED:
                this.testsDisabled++;
                break;
        }

        for (TestCategory i : result.getScoreContainer().getScoreMap().keySet()) {
            scoreContainer.getScoreMap().get(i).setReached(scoreContainer.getScoreMap().get(i).getReached() + result.getScoreContainer().getScoreMap().get(i).getReached());
            scoreContainer.getScoreMap().get(i).setTotal(scoreContainer.getScoreMap().get(i).getTotal() + result.getScoreContainer().getScoreMap().get(i).getTotal());
        }
    }

    public long getTestsFailed() {
        return testsFailed;
    }

    public void setTestsFailed(long testsFailed) {
        this.testsFailed = testsFailed;
    }

    public long getTestsSucceeded() {
        return testsSucceeded;
    }

    public void setTestsSucceeded(long testsSucceeded) {
        this.testsSucceeded = testsSucceeded;
    }

    public long getTestsDisabled() {
        return testsDisabled;
    }

    public void setTestsDisabled(long testsDisabled) {
        this.testsDisabled = testsDisabled;
    }

    public TestEndpointType getTestEndpointType() {
        return testEndpointType;
    }

    public void setTestEndpointType(TestEndpointType testEndpointType) {
        this.testEndpointType = testEndpointType;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }
}
