package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.InternalDiagnosisSets;
import de.rwth.swc.coffee4j.engine.conflict.InternalMissingInvalidTuple;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.*;

/**
 * Splits the constraints of a {@link TestModel} into hard- and soft-constraints which is
 * necessary for {@link DiagnosticConstraintCheckerFactory}.
 * The splitting is based on diagnostic information obtained via a list of {@link InternalMissingInvalidTuple}'s.
 */
class DiagnosticConstraintSplitter {

    /**
     * Splits the constraints of a {@code TestModel} into hard- and soft-constraints.
     *
     * @param testModel             TestModel of which the constraints are split
     * @param toBeNegated           The error-constraint that will be negated is always a hard-constraint
     * @param missingInvalidTuples  Diagnostic information used to split constraints
     * @return                      A pair of hard- and soft-constraint lists. Left-handed side of the pair
     * represents hard-constraints and the right-handed side represents soft-constraints.
     */
    Pair<List<Constraint>, List<Constraint>> splitConstraints(TestModel testModel,
                                                              TupleList toBeNegated,
                                                              List<InternalMissingInvalidTuple> missingInvalidTuples) {
        Preconditions.notNull(testModel);
        Preconditions.notNull(toBeNegated);
        Preconditions.check(testModel.getErrorTupleLists().stream()
                .anyMatch(tupleList -> tupleList.getId() == toBeNegated.getId()));
        Preconditions.notNull(missingInvalidTuples);
        Preconditions.check(missingInvalidTuples.stream()
                .allMatch(mit -> mit.getExplanation() instanceof InternalDiagnosisSets));


        final List<Constraint> hardConstraints = new ArrayList<>();
        final List<Constraint> softConstraints = new ArrayList<>();

        hardConstraints.add(negateConstraint(findErrorConstraintToBeNegated(testModel, toBeNegated)));

        final List<Constraint> remainingConstraints = new ArrayList<>();
        remainingConstraints.addAll(testModel.getExclusionConstraints());
        remainingConstraints.addAll(filterErrorConstraintToBeNegated(testModel, toBeNegated));

        partitionRemainingConstraints(missingInvalidTuples, remainingConstraints, hardConstraints, softConstraints);

        return Pair.of(hardConstraints, softConstraints);
    }

    private void partitionRemainingConstraints(List<InternalMissingInvalidTuple> missingInvalidTuples,
                                               List<Constraint> remainingConstraints,
                                               List<Constraint> hardConstraints,
                                               List<Constraint> softConstraints) {

        for(Constraint constraint : remainingConstraints) {
            if(requiresRelaxation(missingInvalidTuples, constraint)) {
                softConstraints.add(constraint);
            } else {
                hardConstraints.add(constraint);
            }
        }
    }

    private boolean requiresRelaxation(List<InternalMissingInvalidTuple> missingInvalidTuples,
                                       Constraint constraint) {

        for(InternalMissingInvalidTuple tuple : missingInvalidTuples) {
            final InternalDiagnosisSets sets = (InternalDiagnosisSets) tuple.getExplanation();

            for(int[] diagnosisSet : sets.getDiagnosisSets()) {
                final boolean match = Arrays.stream(diagnosisSet)
                        .anyMatch(id -> id == constraint.getTupleList().getId());

                if(match) {
                    return true;
                }
            }
        }

        return false;
    }
}
