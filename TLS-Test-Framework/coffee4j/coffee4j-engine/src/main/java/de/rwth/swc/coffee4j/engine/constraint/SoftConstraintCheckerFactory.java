package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.InternalDiagnosisSets;
import de.rwth.swc.coffee4j.engine.conflict.InternalMissingInvalidTuple;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.checkValidIdentifier;
import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.findErrorConstraintToBeNegated;
import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.filterErrorConstraintToBeNegated;
import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.negateConstraint;

public class SoftConstraintCheckerFactory implements ConstraintCheckerFactory {

    @Override
    public ConstraintChecker createConstraintChecker(TestModel testModel) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ConstraintChecker createConstraintCheckerWithNegation(TestModel testModel, TupleList toBeNegated) {
        Preconditions.notNull(testModel);
        Preconditions.check(checkValidIdentifier(testModel, toBeNegated.getId()));

        final int threshold = computeThreshold(testModel, toBeNegated);

        if(threshold == 0) {
            return new HardConstraintCheckerFactory()
                    .createConstraintCheckerWithNegation(testModel, toBeNegated);
        } else {
            final List<Constraint> hardConstraints = new ArrayList<>();
            hardConstraints.add(negateConstraint(findErrorConstraintToBeNegated(testModel, toBeNegated)));

            final List<Constraint> softConstraints = filterErrorConstraintToBeNegated(testModel, toBeNegated);
            softConstraints.addAll(testModel.getExclusionConstraints());

            return new SoftConstraintChecker(testModel, hardConstraints, softConstraints, threshold);
        }
    }

    private int computeThreshold(TestModel testModel, TupleList toBeNegated) {
        final InternalConflictDiagnosisManager diagnostician = new InternalConflictDiagnosisManager();
        final List<InternalMissingInvalidTuple> missingInvalidTuples = diagnostician.diagnose(testModel, toBeNegated);

        return missingInvalidTuples.size() == 0 ? 0 : missingInvalidTuples.stream()
                .flatMapToInt(tuple ->
                        Arrays.stream(((InternalDiagnosisSets) tuple.getExplanation()).getDiagnosisSets())
                                .mapToInt(diagnosisSet -> diagnosisSet.length))
                .max()
                .orElseThrow();
    }
}
