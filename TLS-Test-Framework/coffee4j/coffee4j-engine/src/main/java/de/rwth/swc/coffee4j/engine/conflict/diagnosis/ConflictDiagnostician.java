package de.rwth.swc.coffee4j.engine.conflict.diagnosis;

import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;

public interface ConflictDiagnostician {

    int[][] getMinimalDiagnoses(InternalConflictSet conflict);
}
