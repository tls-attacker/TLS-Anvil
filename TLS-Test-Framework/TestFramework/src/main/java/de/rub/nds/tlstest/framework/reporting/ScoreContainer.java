package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CVECategory;
import de.rub.nds.tlstest.framework.annotations.categories.CertificateCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.TestCategory;
import de.rub.nds.tlstest.framework.constants.TestResult;
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
                if (i.getAnnoationClass().equals(ComplianceCategory.class)) {
                    scoreMap.put(i, new Score(((ComplianceCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(InteroperabilityCategory.class)) {
                    scoreMap.put(i, new Score(((InteroperabilityCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(SecurityCategory.class)) {
                    scoreMap.put(i, new Score(((SecurityCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(AlertCategory.class)) {
                    scoreMap.put(i, new Score(((AlertCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(CVECategory.class)) {
                    scoreMap.put(i, new Score(((CVECategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(CertificateCategory.class)) {
                    scoreMap.put(i, new Score(((CertificateCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(RecordLayerCategory.class)) {
                    scoreMap.put(i, new Score(((RecordLayerCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(CryptoCategory.class)) {
                    scoreMap.put(i, new Score(((CryptoCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(DeprecatedFeatureCategory.class)) {
                    scoreMap.put(i, new Score(((DeprecatedFeatureCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(HandshakeCategory.class)) {
                    scoreMap.put(i, new Score(((HandshakeCategory)m.getAnnotation(i.getAnnoationClass())).value()));
                } else if (i.getAnnoationClass().equals(MessageStructureCategory.class)) {
                    scoreMap.put(i, new Score(((MessageStructureCategory)m.getAnnotation(i.getAnnoationClass())).value()));
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

    public void updateForResult(TestResult status) {
        for (Score i : scoreMap.values()) {
            i.updateForTestResult(status);
        }
    }

    public void updateStatusForCategory(TestCategory category, TestResult status) {
        if (scoreMap.containsKey(category)) {
            scoreMap.get(category).updateForTestResult(status);
        }
    }

    public void overwriteStatusForCategory(TestCategory category, TestResult status) {
        if (scoreMap.containsKey(category)) {
            scoreMap.get(category).overwiteTestResult(status);
        }
    }

    public Map<TestCategory, Score> getScoreMap() {
        return scoreMap;
    }
}
