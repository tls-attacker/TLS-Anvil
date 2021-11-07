package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.*;
import java.util.stream.Collectors;

public class ReduceBasedDiagnosisHittingSetBuilder {

    private final TestModel testModel;

    public ReduceBasedDiagnosisHittingSetBuilder(TestModel testModel) {
        Preconditions.notNull(testModel);

        this.testModel = testModel;
    }

    public List<DiagnosisHittingSet> computeMinimalDiagnosisHittingSets(List<MissingInvalidTuple> mits) {
        Preconditions.notNull(mits);
        Preconditions.check(mits.size() > 0);
        Preconditions.check(mits.stream().allMatch(mit -> isDiagnosisSetsOrInconsistentBackground(mit.getExplanation())));

        final List<MissingInvalidTuple> extendedMits = extendWithDiagnosisSetsforNegatedErrorConstraints(mits);

        final List<Set<Set<DiagnosisElement>>> sets = extendedMits.stream()
                .map(mit -> new HashSet<Set<DiagnosisElement>>(
                        ((DiagnosisSets) mit.getExplanation()).getDiagnosisSets().stream()
                                .map(ds -> new HashSet<>(ds.getDiagnosisElements()))
                        .collect(Collectors.toSet())))
                .collect(Collectors.toList());

        final Set<Set<DiagnosisElement>> selections = sets.stream()
                .reduce(Collections.emptySet(), this::reduceToDiagnosisHittingSets);

        return selections.stream()
                .map(selection -> new DiagnosisHittingSet(new ArrayList<>(selection)))
                .collect(Collectors.toList());
    }

    private Set<Set<DiagnosisElement>> reduceToDiagnosisHittingSets(Set<Set<DiagnosisElement>> a, Set<Set<DiagnosisElement>> b) {
        if(a.isEmpty()) {
            return b;
        }

        if(b.isEmpty()) {
            return a;
        }

        final Set<Set<DiagnosisElement>> sets = new LinkedHashSet<>(a.size() * b.size());

        for(Set<DiagnosisElement> aSet : a) {
            for(Set<DiagnosisElement> bSet : b) {

                final Set<DiagnosisElement> combined = new LinkedHashSet<>(aSet.size() + bSet.size());
                combined.addAll(aSet);
                combined.addAll(bSet);

                sets.add(combined);
            }
        }

        return filterMinimalDiagnosisHittingSets(sets);
    }

    Set<Set<DiagnosisElement>> filterMinimalDiagnosisHittingSets(Set<Set<DiagnosisElement>> selections) {
        final Set<Set<DiagnosisElement>> filtered = new LinkedHashSet<>();

        for(Set<DiagnosisElement> selection : selections) {
            if(isMinimalDiagnosisHittingSet(selection, selections)) {
                filtered.add(selection);
            }
        }

        return filtered;
    }

    boolean isMinimalDiagnosisHittingSet(Set<DiagnosisElement> candidate, Set<Set<DiagnosisElement>> diagnosisHittingSets) {
        if(candidate.size() == 1) {
            return true;
        }

        for(Set<DiagnosisElement> other : diagnosisHittingSets) {
            if(candidate != other) {
                if (coversAnotherDiagnosisHittingSet(candidate, other)) {
                    return false;
                }
            }
        }

        return true;
    }

    private boolean coversAnotherDiagnosisHittingSet(Set<DiagnosisElement> candidate, Set<DiagnosisElement> other) {
        if(other.size() > candidate.size()) {
            return false;
        }

        for(DiagnosisElement otherElement : other) {
            if(!containsElement(otherElement, candidate)) {
                return false;
            }
        }

        return true;
    }

    private boolean containsElement(DiagnosisElement element, Set<DiagnosisElement> otherElements) {
        for(DiagnosisElement otherElement : otherElements) {
            if (element.equals(otherElement)) {
                return true;
            }
        }

        return false;
    }

    private boolean isDiagnosisSetsOrInconsistentBackground(ConflictExplanation explanation) {
        return explanation instanceof DiagnosisSets || explanation instanceof InconsistentBackground;
    }

    private List<MissingInvalidTuple> extendWithDiagnosisSetsforNegatedErrorConstraints(List<MissingInvalidTuple> mits) {
        return mits.stream()
                .map(this::extendWithDiagnosisSetsForNegatedErrorConstraint)
                .collect(Collectors.toList());
    }

    MissingInvalidTuple extendWithDiagnosisSetsForNegatedErrorConstraint(MissingInvalidTuple mit) {
        final List<DiagnosisSet> diagnosisSetList = copyDiagnosisSets(mit.getExplanation());

        if(!isMarkedAsCorrect(mit.getNegatedErrorConstraintId())) {
            diagnosisSetList.add(new DiagnosisSet(Collections.singletonList(
                    new DiagnosisElement(mit.getNegatedErrorConstraintId(), mit.getInvolvedParameters(), mit.getMissingValues()))
            ));
        }

        final ConflictSet rootConflictSet = copyRootConflictSet(mit.getExplanation());

        final DiagnosisSets diagnosisSets = new DiagnosisSets(rootConflictSet, diagnosisSetList);

        return new MissingInvalidTuple(
                mit.getNegatedErrorConstraintId(),
                mit.getInvolvedParameters(),
                mit.getMissingValues(),
                diagnosisSets);
    }

    private List<DiagnosisSet> copyDiagnosisSets(ConflictExplanation explanation) {
        if(explanation instanceof DiagnosisSets) {
            final DiagnosisSets oldDiagnosisSets = (DiagnosisSets) explanation;

            return new ArrayList<>(oldDiagnosisSets.getDiagnosisSets());
        } else if(explanation instanceof InconsistentBackground) {
            return new ArrayList<>();
        } else {
            throw new IllegalStateException();
        }
    }

    private ConflictSet copyRootConflictSet(ConflictExplanation explanation) {
        if(explanation instanceof DiagnosisSets) {
            final DiagnosisSets oldDiagnosisSets = (DiagnosisSets) explanation;

            return oldDiagnosisSets.getRootConflictSet();
        } else if(explanation instanceof InconsistentBackground) {
            final InconsistentBackground background = (InconsistentBackground) explanation;

            return new ConflictSet(background.getConflictElements());
        } else {
            throw new IllegalStateException();
        }
    }

    private boolean isMarkedAsCorrect(int constraintId) {
        return findConstraint(constraintId).isMarkedAsCorrect();
    }

    private TupleList findConstraint(int constraintId) {
        return testModel.getForbiddenTupleLists().stream()
                .filter(tupleList -> tupleList.getId() == constraintId)
                .findFirst()
                .or(() -> testModel.getErrorTupleLists().stream()
                        .filter(tupleList -> tupleList.getId() == constraintId)
                        .findFirst())
                .orElseThrow();
    }
}
