package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.conflict.DiagnosisHittingSet;
import de.rwth.swc.coffee4j.engine.conflict.MissingInvalidTuple;

import java.util.List;

public interface ConflictDetectionReporter {

    void reportDetectedMissingInvalidTuples(List<MissingInvalidTuple> missingInvalidTuples);

    void reportMinimalDiagnosisHittingSets(List<DiagnosisHittingSet> minimalHittingSets);
}
