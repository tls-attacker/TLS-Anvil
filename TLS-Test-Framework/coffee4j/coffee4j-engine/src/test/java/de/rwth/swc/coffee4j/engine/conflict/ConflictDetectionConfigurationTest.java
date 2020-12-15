package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.conflict.diagnosis.ExhaustiveConflictDiagnostician;
import de.rwth.swc.coffee4j.engine.conflict.explanation.QuickConflictExplainer;
import org.junit.jupiter.api.Test;

import static org.testng.Assert.assertThrows;

class ConflictDetectionConfigurationTest {

    @Test
    void testDisabledConflictDetection() {
        new ConflictDetectionConfiguration(
                false,
                false,
                false,
                null,
                false,
                null);
    }

    @Test
    void testEnableConflictExplanation() {
        new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                false,
                null);
    }

    @Test
    void testEnableConflictExplanationNoClass() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ConflictDetectionConfiguration(
                        true,
                        false,
                        true,
                        null,
                        false,
                        null)
        );
    }

    @Test
    void testEnableConflictDiagnostician() {
        new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                true,
                ExhaustiveConflictDiagnostician.class);
    }

    @Test
    void testEnableConflictDiagnosticianNoClass() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ConflictDetectionConfiguration(
                        true,
                        false,
                        true,
                        QuickConflictExplainer.class,
                        true,
                        null)
        );
    }
}
