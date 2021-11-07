package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.choco.ChocoModel;
import de.rwth.swc.coffee4j.engine.conflict.diagnosis.ConflictDiagnostician;
import de.rwth.swc.coffee4j.engine.conflict.diagnosis.ExhaustiveConflictDiagnostician;
import de.rwth.swc.coffee4j.engine.conflict.explanation.ConflictExplainer;
import de.rwth.swc.coffee4j.engine.conflict.explanation.QuickConflictExplainer;
import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;
import de.rwth.swc.coffee4j.engine.conflict.InternalDiagnosisSets;
import de.rwth.swc.coffee4j.engine.conflict.InternalMissingInvalidTuple;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntArraySet;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

class InternalConflictDiagnosisManager {

    private final ConflictExplainer explainer;
    private final ConflictDiagnostician diagnostician;

    InternalConflictDiagnosisManager() {
        this.explainer = new QuickConflictExplainer();
        this.diagnostician = new ExhaustiveConflictDiagnostician();
    }

    List<InternalMissingInvalidTuple> diagnose(TestModel testModel, TupleList toBeNegated) {
        Preconditions.notNull(testModel);
        Preconditions.notNull(toBeNegated);
        Preconditions.check(testModel.getErrorTupleLists().stream()
                .anyMatch(tupleList -> tupleList.getId() == toBeNegated.getId()));

        final List<InternalMissingInvalidTuple> missingInvalidTuples = new ArrayList<>();

        final List<Constraint> constraints = new ArrayList<>();
        constraints.addAll(testModel.getExclusionConstraints());
        constraints.addAll(testModel.getErrorConstraints());

        final ChocoModel chocoModel = new ChocoModel(testModel.getParameterSizes(), constraints);
        chocoModel.setNegationOfConstraint(toBeNegated.getId());

        final IntSet background = new IntArraySet();
        background.add(toBeNegated.getId());

        final IntSet relaxable = new IntArraySet();
        relaxable.addAll(constraints.stream()
                .filter(constraint -> constraint.getTupleList().getId() != toBeNegated.getId())
                .map(constraint -> constraint.getTupleList().getId())
                .collect(Collectors.toList()));

        for(int[] tuple : toBeNegated.getTuples()) {
            chocoModel.reset();

            final int assignmentId = chocoModel.setAssignmentConstraint(toBeNegated.getInvolvedParameters(), tuple);

            background.add(assignmentId);

            final Optional<InternalDiagnosisSets> optional = runConflictDiagnosis(chocoModel, background, relaxable);

            optional.ifPresent(explanation -> missingInvalidTuples.add(
                    new InternalMissingInvalidTuple(
                            toBeNegated.getId(), toBeNegated.getInvolvedParameters(), tuple, explanation)));

            chocoModel.clearAssignmentConstraint();
            background.remove(assignmentId);
        }

        return missingInvalidTuples;
    }

    private Optional<InternalDiagnosisSets> runConflictDiagnosis(ChocoModel chocoModel,
                                                                 IntSet background,
                                                                 IntSet relaxable) {
        return chocoModel.isSatisfiable() ? Optional.empty() :
                explainer.getMinimalConflict(chocoModel, background.toIntArray(), relaxable.toIntArray())
                        .filter(explanation -> explanation instanceof InternalConflictSet)
                        .map(explanation -> (InternalConflictSet) explanation)
                        .map(explanation -> new InternalDiagnosisSets(
                                explanation,
                                diagnostician.getMinimalDiagnoses(explanation)));
    }
}