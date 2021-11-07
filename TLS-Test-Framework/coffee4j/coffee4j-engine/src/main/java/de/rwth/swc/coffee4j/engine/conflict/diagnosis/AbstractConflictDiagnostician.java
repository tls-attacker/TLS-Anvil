package de.rwth.swc.coffee4j.engine.conflict.diagnosis;

import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;
import de.rwth.swc.coffee4j.engine.conflict.InternalExplanation;
import de.rwth.swc.coffee4j.engine.conflict.explanation.QuickConflictExplainer;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.*;

import static de.rwth.swc.coffee4j.engine.util.ArrayUtil.contains;
import static de.rwth.swc.coffee4j.engine.util.ArrayUtil.exclude;

/**
 * Computes minimal diagnoses (deltas to relax minimal conflict sets) for a given conflict problem.
 * <p>
 * This implementation is based on the following paper.
 * Reiter, Raymond (1987).
 * A theory of conflict from first principles.
 * Artificial intelligence, 1987, 32. Jg., Nr. 1, S. 57-95.
 */
abstract class AbstractConflictDiagnostician implements ConflictDiagnostician {

    void expandNextNode(InternalConflictSet conflict,
                        List<int[]> diagnoses,
                        Queue<int[]> pathsToExpand) {
        final int[] relaxedConstraintIds = pathsToExpand.remove();

        if(!isCurrentPathAlreadyCoveredByDiagnoses(relaxedConstraintIds, diagnoses)) {
            /* isCurrentPathAlreadyCoveredByDiagnoses(relaxedConstraintIds, diagnoses) == true: the current node is pruned */
            final Optional<int[]> optional = computeMinimalConflict(conflict, relaxedConstraintIds);

            if(optional.isEmpty()) {
                diagnoses.add(relaxedConstraintIds);
            } else {
                final int[] conflictSet = optional.get();

                pathsToExpand.addAll(expandPaths(relaxedConstraintIds, conflictSet));
            }
        }
    }

    private Optional<int[]> computeMinimalConflict(InternalConflictSet conflict, int[] currentPath) {
        final Optional<InternalExplanation> optional = new QuickConflictExplainer().getMinimalConflict(
                conflict.getChocoModel(),
                conflict.getBackground(),
                exclude(conflict.getRelaxable(), currentPath));

        return optional.flatMap(explanation -> {
            if(explanation instanceof InternalConflictSet) {
                return Optional.of(
                        ((InternalConflictSet) explanation).getConflictSet()
                );
            } else {
                return Optional.empty();
            }
        });
    }

    boolean isCurrentPathAlreadyCoveredByDiagnoses(int[] currentPath,
                                                   List<int[]> diagnoses) {
        Preconditions.notNull(currentPath);
        Preconditions.notNull(diagnoses);
        Preconditions.check(currentPath.length > 0);

        return diagnoses.stream()
                .anyMatch(diagnosis -> isSubset(diagnosis, currentPath));
    }

    /* checks if all elements of subset are contained by superset */
    boolean isSubset(int[] subset, int[] superset) {
        Preconditions.notNull(subset);
        Preconditions.notNull(superset);

        if(subset.length > superset.length) {
            return false;
        }

        for(int element : subset) {
            if(!contains(superset, element)) {
                return false;
            }
        }

        return true;
    }

    List<int[]> expandPaths(int[] path, int[] extensions) {
        Preconditions.notNull(path);
        Preconditions.notNull(extensions);
        Preconditions.check(extensions.length > 0);

        final int[][] expansions = new int[extensions.length][];

        for(int i = 0; i < expansions.length; i++) {
            expansions[i] = new int[path.length + 1];

            System.arraycopy(path, 0, expansions[i], 0, path.length);
            expansions[i][path.length] = extensions[i];
        }

        return Arrays.asList(expansions);
    }
}
