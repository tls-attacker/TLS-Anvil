package de.rwth.swc.coffee4j.engine.conflict.diagnosis;

import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;

import java.util.*;

public class FastConflictDiagnostician extends AbstractConflictDiagnostician {

    public int[][] getMinimalDiagnoses(InternalConflictSet conflict) {
        final List<int[]> diagnoses = new ArrayList<>();
        final Queue<int[]> pathsToExpand = new LinkedList<>(expandPaths(new int[0], conflict.getConflictSet()));

        while(!pathsToExpand.isEmpty()) {
            expandNextNode(conflict, diagnoses, pathsToExpand);

            if(!diagnoses.isEmpty()) {
                return new int[][] { diagnoses.get(0) };
            }
        }

        return new int[0][];
    }
}
