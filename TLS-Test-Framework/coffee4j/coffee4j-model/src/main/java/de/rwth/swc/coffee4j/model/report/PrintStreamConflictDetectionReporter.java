package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.*;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.List;

public class PrintStreamConflictDetectionReporter implements  ConflictDetectionReporter {

    private final PrintStream printStream;
    private final ModelConverter modelConverter;

    public PrintStreamConflictDetectionReporter(PrintStream printStream, ModelConverter modelConverter) {
        Preconditions.notNull(printStream);
        Preconditions.notNull(modelConverter);

        this.printStream = printStream;
        this.modelConverter = modelConverter;
    }

    @Override
    public void reportDetectedMissingInvalidTuples(List<MissingInvalidTuple> missingInvalidTuples) {
        printStream.println("ERROR: Conflicts among constraints detected!");
        printStream.println("--------------------------------------------");
        printStream.println();

        for(MissingInvalidTuple missingInvalidTuple : missingInvalidTuples) {
            reportMissingInvalidTuple(missingInvalidTuple);
        }

        printStream.println("Please repair the constraints and re-run the tests.");
        printStream.println();
    }

    @Override
    public void reportMinimalDiagnosisHittingSets(List<DiagnosisHittingSet> minimalHittingSets) {
        printStream.println("ERROR: Conflicts among constraints detected!");
        printStream.println("--------------------------------------------");

        for(DiagnosisHittingSet set : minimalHittingSets) {
            reportMinimalDiagnosisHittingSet(set);
        }

        printStream.println("Please repair the constraints and re-run the tests.");
        printStream.println();
    }

    private void reportMinimalDiagnosisHittingSet(DiagnosisHittingSet set) {
        printStream.println("Relax the constraints as follows.");

        for(DiagnosisElement element : set.getDiagnosisElements()) {
            final Combination combination = findCombination(
                    element.getInvolvedParameters(),
                    element.getConflictingValues());
            final Constraint diagnosedConstraint = findConstraint(element.getDiagnosedConstraintId());

            printStream.println("\tRemove " + combination + " from " + diagnosedConstraint + ".");
        }

        printStream.println();
    }

    private void reportMissingInvalidTuple(MissingInvalidTuple missingInvalidTuple) {
        final Combination combination = findCombination(
                missingInvalidTuple.getInvolvedParameters(),
                missingInvalidTuple.getMissingValues());

        final Constraint negatedErrorConstraint = findConstraint(missingInvalidTuple.getNegatedErrorConstraintId());

        printStream.println("For error-constraint \n\t" + negatedErrorConstraint + ",\n\t" + combination + "\nis missing.");
        printStream.println();

        reportExplanation(missingInvalidTuple.getExplanation());

        printStream.println();
    }

    private void reportExplanation(ConflictExplanation explanation) {
        if(explanation instanceof UnknownConflictExplanation) {
            reportUnknownExplanation();
        } else if(explanation instanceof InconsistentBackground) {
            reportInconsistentBackground((InconsistentBackground) explanation);
        } else if(explanation instanceof ConflictSet) {
            reportConflictSet((ConflictSet) explanation);
        } else if(explanation instanceof DiagnosisSets) {
            reportDiagnosisSet((DiagnosisSets) explanation);
        } else {
            throw new IllegalStateException();
        }
    }

    private void reportUnknownExplanation() {
        printStream.println("For more information, enable conflict explanation and diagnosis.");
    }

    private void reportInconsistentBackground(InconsistentBackground explanation) {
        printStream.println("\tThe constraint itself is incorrect.");
    }

    private void reportConflictSet(ConflictSet conflictSet) {
        printStream.println("The interaction with the following constraints is causing the absence:");

        for(ConflictElement element : conflictSet.getConflictElements()) {
            final Combination combination = findCombination(element.getInvolvedParameters(), element.getConflictingValues());
            final Constraint constraint = findConstraint(element.getConflictingConstraintId());

            printStream.println("\t" + constraint + " with " + combination);
        }
    }

    private void reportDiagnosisSet(DiagnosisSets diagnosisSets) {
        for(DiagnosisSet diagnosis : diagnosisSets.getDiagnosisSets()) {
            reportDiagnosis(diagnosis);
        }
    }

    private void reportDiagnosis(DiagnosisSet diagnosis) {
        printStream.println("As a diagnosis, relax ");

        for(DiagnosisElement element : diagnosis.getDiagnosisElements()) {
            final Combination combination = findCombination(element.getInvolvedParameters(), element.getConflictingValues());
            final Constraint constraint = findConstraint(element.getDiagnosedConstraintId());

            printStream.println("\t" + combination + " of " + constraint);
        }

        printStream.println("to remove all conflicts.");
    }

    private int[] convertTupleFromDualRepresentation(int[] parameters, int[] values) {
        final int[] convertedTuple = new int[modelConverter.getConvertedModel().getParameterSizes().length];
        Arrays.fill(convertedTuple, CombinationUtil.NO_VALUE);

        for(int i = 0; i < parameters.length; i++) {
            int parameter = parameters[i];
            int value = values[i];

            convertedTuple[parameter] = value;
        }

        return convertedTuple;
    }

    private Combination findCombination(int[] parameters, int[] values) {
        final int [] tuple = convertTupleFromDualRepresentation(parameters, values);

        return modelConverter.convertCombination(tuple);
    }

    private Constraint findConstraint(int id) {
        final TupleList negatedTupleList = modelConverter.getConvertedModel().getErrorTupleLists()
                .stream()
                .filter(tupleList -> tupleList.getId() == id)
                .findFirst().orElseThrow();

        return modelConverter.convertConstraint(negatedTupleList);
    }
}
