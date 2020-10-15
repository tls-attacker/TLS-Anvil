package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.TestCategory;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class ScoreContainer {
    private static final Logger LOGGER = LogManager.getLogger();

    @JsonProperty("Score")
    Map<TestCategory, Score> scoreMap = new HashMap<>();


    public ScoreContainer() {

    }

    public ScoreContainer(ExtensionContext context) {
        Method m = context.getRequiredTestMethod();

        for (TestCategory i : TestCategory.values()) {
            if (m.isAnnotationPresent(i.getAnnoationClass())) {

                if (i.getAnnoationClass().equals(Compliance.class)) {
                    scoreMap.put(i, new Score(((Compliance)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(Interoperability.class)) {
                    scoreMap.put(i, new Score(((Interoperability)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(Security.class)) {
                    scoreMap.put(i, new Score(((Security)m.getAnnotation(i.getAnnoationClass())).value()));
                } else {
                    throw new RuntimeException("Unknown TestCategory, cannot create ScoreContainer");
                }
            }
        }
    }

    public static ScoreContainer forEveryCategory() {
        ScoreContainer container = new ScoreContainer();
        for (TestCategory i : TestCategory.values()) {
            container.scoreMap.put(i, new Score());
        }
        return container;
    }


    public void updateMaxScoreMultiplier(TestCategory category, int max) {
        if (scoreMap.containsKey(category)) {
            scoreMap.get(category).setMax(max);
        }
    }

    public void updateForStatus(TestStatus status) {
        for (Score i : scoreMap.values()) {
            i.updateForTestStatus(status);
        }
    }

    public void updateStatusForCategory(TestCategory category, TestStatus status) {
        if (scoreMap.containsKey(category)) {
            scoreMap.get(category).updateForTestStatus(status);
        }
    }

    public void overwriteStatusForCategory(TestCategory category, TestStatus status) {
        if (scoreMap.containsKey(category)) {
            scoreMap.get(category).overwiteTestStatus(status);
        }
    }

    public Map<TestCategory, Score> getScoreMap() {
        return scoreMap;
    }
}
