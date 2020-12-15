package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.ints.IntArraySet;
import it.unimi.dsi.fastutil.ints.IntList;
import it.unimi.dsi.fastutil.ints.IntLists;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

class TestModelExpander {

    private final int factor;
    private final TestModel testModel;

    TestModelExpander(TestModel testModel) {
        Preconditions.notNull(testModel);

        this.testModel = testModel;
        this.factor = computeFactor(testModel);
    }

    int getFactor() {
        return factor;
    }

    TestModel createExpandedTestModel() {
        final List<TupleList> forbiddenTuples = expandTupleLists(testModel.getForbiddenTupleLists());
        final List<TupleList> errorTuples = expandTupleLists(testModel.getErrorTupleLists());

        return new TestModel(testModel.getStrength(), testModel.getParameterSizes(), forbiddenTuples, errorTuples);
    }

    int computeOriginalId(TupleList tupleList) {
        return computeOriginalId(tupleList.getId());
    }

    int computeOriginalId(int id) {
        Preconditions.check(id > 0);

        return id / factor;
    }

    int computeOriginalIndexInTupleList(TupleList tupleList) {
        Preconditions.notNull(tupleList);

        return tupleList.getId() % factor;
    }

    private List<TupleList> expandTupleLists(List<TupleList> tupleLists) {
        return tupleLists
                .stream()
                .flatMap(tupleList -> IntStream
                        .range(0, tupleList.getTuples().size())
                        .mapToObj(i -> new TupleList(
                                computeExpandedId(tupleList, i),
                                tupleList.getInvolvedParameters(),
                                Collections.singletonList(tupleList.getTuples().get(i)),
                                tupleList.isMarkedAsCorrect())))
                .collect(Collectors.toList());
    }

    private int computeExpandedId(TupleList tupleList, int tupleIndex) {
        return tupleList.getId() * factor + tupleIndex;
    }

    private int computeFactor(TestModel testModel) {
        final int tupleLists = testModel.getForbiddenTupleLists().size() + testModel.getErrorTupleLists().size();
        final int maxTuples = Math.max(
                testModel.getForbiddenTupleLists().stream().mapToInt(tupelList -> tupelList.getTuples().size()).max().orElse(0),
                testModel.getErrorTupleLists().stream().mapToInt(tupelList -> tupelList.getTuples().size()).max().orElse(0)
        );

        return computeFactor(tupleLists, maxTuples);
    }

    private int computeFactor(int tupleLists, int maxTuples) {
        int power = 1;

        if(tupleLists > 0) {
            while(tupleLists / ((int) Math.pow(10, power)) != 0) {
                power += 1;
            }
        }

        if(maxTuples > 0) {
            while(maxTuples / ((int) Math.pow(10, power)) != 0) {
                power += 1;
            }
        }

        return (int) Math.pow(10, power);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TestModelExpander expander = (TestModelExpander) o;
        return factor == expander.factor &&
                testModel.equals(expander.testModel);
    }

    @Override
    public int hashCode() {
        return Objects.hash(factor, testModel);
    }

    @Override
    public String toString() {
        return "TestModelExpander{" +
                "factor=" + factor +
                ", testModel=" + testModel +
                '}';
    }
}
