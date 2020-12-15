package de.rwth.swc.coffee4j.engine.conflict.diagnosis;

import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;

public class NoConflictDiagnostician implements ConflictDiagnostician {

    @Override
    public int[][] getMinimalDiagnoses(InternalConflictSet conflict) {
        return new int[0][];
    }
}
