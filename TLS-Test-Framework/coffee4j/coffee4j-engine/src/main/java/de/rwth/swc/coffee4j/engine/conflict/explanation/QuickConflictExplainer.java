package de.rwth.swc.coffee4j.engine.conflict.explanation;

import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;
import de.rwth.swc.coffee4j.engine.conflict.InternalExplanation;
import de.rwth.swc.coffee4j.engine.conflict.InternalInconsistentBackground;
import de.rwth.swc.coffee4j.engine.conflict.choco.ChocoModel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntArraySet;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.Arrays;
import java.util.Optional;

/**
 * Algorithm to find a minimal conflict for an over-constrained CSP
 * <p>
 * This implementation is based on the following paper.
 * Junker, Ulrich. (2004).
 * DefaultConflictExplainer: Preferred explanations and relaxations for over-constrained problems.
 * AAAI. 167 - 172.
 */
public class QuickConflictExplainer implements ConflictExplainer {

    /**
     * Finds a preferred explanation for an over-constrained CSP
     *
     * @param model       CSP which included backgrounds and constraints
     * @param background  consistent set of constraints that cannot be relaxed
     * @param relaxable inconsistent constraints that can be relaxed
     * @return  null if there is no conflict
     *          an empty array if a preferred explanation could not be obtained
     *          background if background is inconsistent
     *          otherwise, a subset of relaxable constraints
     */
    public Optional<InternalExplanation> getMinimalConflict(ChocoModel model,
                                                            int[] background,
                                                            int[] relaxable) {
        Preconditions.notNull(model);
        Preconditions.notNull(background);
        Preconditions.notNull(relaxable);
        Preconditions.check(relaxable.length > 0);

        if (isConsistent(model, union(background, relaxable))) {
            model.enableAllConstraints();

            return Optional.empty();
        }

        if(!isConsistent(model, background)) {
            model.enableAllConstraints();

            return Optional.of(
                    new InternalInconsistentBackground(background, relaxable)
            );
        }

        final int[] conflictSet = doExplain(model, background, background, relaxable);

        model.enableAllConstraints();

        return Optional.of(
                new InternalConflictSet(model, background, relaxable, conflictSet)
        );
    }

    private boolean isConsistent(ChocoModel model, int[] constraints) {
        model.disableAllConstraints();
        model.reset();
        model.enableConstraints(constraints);

        return model.isSatisfiable();
    }

    private int[] doExplain(ChocoModel problem, int[] background, int[] delta, int[] relaxable) {
        if (delta.length != 0 && !isConsistent(problem, background)) {
            return new int[0];
        }

        if (relaxable.length == 1) {
            return relaxable;
        }

        final int k = relaxable.length / 2;
        int[] constraints1 = Arrays.copyOfRange(relaxable, 0, k);
        int[] constraints2 = Arrays.copyOfRange(relaxable, k, relaxable.length);

        int[] delta2 = doExplain(problem, union(background, constraints1), constraints1, constraints2);
        int[] delta1 = doExplain(problem, union(background, delta2), delta2, constraints1);

        return distinctUnion(delta1, delta2);
    }

    private int[] union(int[] a, int[] b) {
        int[] array = new int[a.length + b.length];

        System.arraycopy(a, 0, array, 0, a.length);
        System.arraycopy(b, 0, array, a.length, b.length);

        return array;
    }

    private int[] distinctUnion(int[] a, int[] b) {
        final IntSet set = new IntArraySet();
        Arrays.stream(a).forEach(set::add);
        Arrays.stream(b).forEach(set::add);

        return set.toIntArray();
    }
}
