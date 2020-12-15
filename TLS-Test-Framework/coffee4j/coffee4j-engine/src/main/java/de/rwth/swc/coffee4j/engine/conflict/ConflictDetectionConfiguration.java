package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.conflict.diagnosis.ConflictDiagnostician;
import de.rwth.swc.coffee4j.engine.conflict.diagnosis.NoConflictDiagnostician;
import de.rwth.swc.coffee4j.engine.conflict.explanation.ConflictExplainer;
import de.rwth.swc.coffee4j.engine.conflict.explanation.NoConflictExplainer;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.lang.reflect.InvocationTargetException;
import java.util.Objects;

public class ConflictDetectionConfiguration {

    public static ConflictDetectionConfiguration disable() {
        return new ConflictDetectionConfiguration(false, false, false, null, false, null);
    }

    private final boolean conflictDetectionEnabled;
    private final boolean shouldAbort;
    private final boolean conflictExplanationEnabled;
    private final Class<? extends ConflictExplainer> conflictExplainerClass;
    private final boolean conflictDiagnosisEnabled;
    private final Class<? extends ConflictDiagnostician> conflictDiagnosticianClass;

    private boolean implies(boolean a, boolean b) {
        return !a || b;
    }

    public ConflictDetectionConfiguration(boolean conflictDetectionEnabled,
                                          boolean shouldAbort,
                                          boolean conflictExplanationEnabled,
                                          Class<? extends ConflictExplainer> conflictExplainerClass,
                                          boolean conflictDiagnosisEnabled,
                                          Class<? extends ConflictDiagnostician> conflictDiagnosticianClass) {
        Preconditions.check(implies(conflictExplanationEnabled, conflictDetectionEnabled));
        Preconditions.check(implies(conflictExplanationEnabled, conflictExplainerClass != null));
        Preconditions.check(implies(conflictDiagnosisEnabled, conflictExplanationEnabled));
        Preconditions.check(implies(conflictDiagnosisEnabled, conflictDiagnosticianClass != null));

        this.conflictDetectionEnabled = conflictDetectionEnabled;
        this.shouldAbort = shouldAbort;
        this.conflictExplanationEnabled = conflictExplanationEnabled;

        if(!conflictExplanationEnabled) {
            this.conflictExplainerClass = NoConflictExplainer.class;
        } else  {
            this.conflictExplainerClass = conflictExplainerClass;
        }

        this.conflictDiagnosisEnabled = conflictDiagnosisEnabled;

        if(!conflictDiagnosisEnabled) {
            this.conflictDiagnosticianClass = NoConflictDiagnostician.class;
        } else {
            this.conflictDiagnosticianClass = conflictDiagnosticianClass;
        }
    }

    public boolean isConflictDetectionEnabled() {
        return conflictDetectionEnabled;
    }

    public boolean shouldAbort() {
        return shouldAbort;
    }

    public boolean isConflictExplanationEnabled() {
        return conflictExplanationEnabled;
    }

    public Class<? extends ConflictExplainer> getConflictExplainerClass() {
        return conflictExplainerClass;
    }

    public boolean isConflictDiagnosisEnabled() {
        return conflictDiagnosisEnabled;
    }

    public Class<? extends ConflictDiagnostician> getConflictDiagnosticianClass() {
        return conflictDiagnosticianClass;
    }

    public ConflictExplainer createConflictExplainer() {
        try {
            return conflictExplainerClass.getConstructor().newInstance();
        } catch (InstantiationException | NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public ConflictDiagnostician createConflictDiagnostician() {
        try {
            return conflictDiagnosticianClass.getConstructor().newInstance();
        } catch (InstantiationException | NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public TestModelExpander createTestModelExpander(TestModel testModel) {
        return new TestModelExpander(testModel);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConflictDetectionConfiguration that = (ConflictDetectionConfiguration) o;
        return conflictDetectionEnabled == that.conflictDetectionEnabled &&
                shouldAbort == that.shouldAbort &&
                conflictExplanationEnabled == that.conflictExplanationEnabled &&
                conflictDiagnosisEnabled == that.conflictDiagnosisEnabled &&
                Objects.equals(conflictExplainerClass, that.conflictExplainerClass) &&
                Objects.equals(conflictDiagnosticianClass, that.conflictDiagnosticianClass);
    }

    @Override
    public int hashCode() {
        return Objects.hash(conflictDetectionEnabled, shouldAbort, conflictExplanationEnabled, conflictExplainerClass, conflictDiagnosisEnabled, conflictDiagnosticianClass);
    }

    @Override
    public String toString() {
        return "ConflictDetectionConfiguration{" +
                "conflictDetectionEnabled=" + conflictDetectionEnabled +
                ", shouldAbort=" + shouldAbort +
                ", conflictExplanationEnabled=" + conflictExplanationEnabled +
                ", conflictExplainerClass=" + conflictExplainerClass +
                ", conflictDiagnosisEnabled=" + conflictDiagnosisEnabled +
                ", conflictDiagnosticianClass=" + conflictDiagnosticianClass +
                '}';
    }
}
