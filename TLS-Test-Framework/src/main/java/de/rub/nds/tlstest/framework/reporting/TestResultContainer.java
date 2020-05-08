package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import org.junit.platform.launcher.TestIdentifier;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
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

    public TestResultContainer(TestIdentifier identifier) {
        this.uniqueId = identifier.getUniqueId();
        this.displayName = identifier.getDisplayName();
    }

    public TestResultContainer() { }

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

    public void addResultWithParent(String parentId, AnnotatedStateContainer result) {
        TestResultContainer container = this.getContainerWithId(parentId);
        container.addResult(result);
    }

    public Map<String, TestResultContainer> getChildren() {
        return children;
    }

    public void setChildren(Map<String, TestResultContainer> children) {
        this.children = children;
    }

    public void addChildContainer(String uniqueId, TestResultContainer container) {
        this.children.put(uniqueId, container);
    }

    public void addChildContainer(TestIdentifier container) {
        if (!container.getParentId().isPresent()) {
            throw new RuntimeException("Could not add child container");
        }
        String parentId = container.getParentId().get();
        if (parentId.equals(uniqueId)) {
            TestResultContainer c = new TestResultContainer(container);
            this.children.put(container.getUniqueId(), c);
            return;
        }

        TestResultContainer parentContainer = getContainerWithId(parentId);
        if (parentContainer == null) {
            throw new RuntimeException("Could not add child container");
        }

        parentContainer.addChildContainer(container);
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
}
