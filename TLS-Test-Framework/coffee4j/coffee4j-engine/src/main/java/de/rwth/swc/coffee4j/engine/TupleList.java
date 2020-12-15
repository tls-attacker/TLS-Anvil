package de.rwth.swc.coffee4j.engine;

import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Class representing a constraint via storing all sub-combinations which are not allowed. Instead of storing complete
 * sub-combinations (with field having {@link CombinationUtil#NO_VALUE}), only
 * the values of parameters actually constrained are saved. This means that if the test input [0, 1, 2, 3, 4]
 * should not be allowed by this constraint and the constraint operates on the first and third parameter,
 * only [0, 2] will be stored.
 */
public class TupleList {
    
    private final int id;
    private final int[] involvedParameters;
    private final List<int[]> tuples;
    private final boolean markedAsCorrect;

    public TupleList(final int id, final int[] involvedParameters, final Collection<int[]> tuples) {
        this(id, involvedParameters, tuples, false);
    }

    /**
     * Creates a new tuple list out of a given id, the involved parameters, and a collection of tuples which should
     * not be allowed. The tuples should be in the format specified by {@link TupleList}.
     *
     * @param id                 the id of the list. This should be unique per {@link TestModel}
     * @param involvedParameters the indices of all involved parameters
     * @param tuples             all tuples which are not allowed
     */
    public TupleList(final int id, final int[] involvedParameters, final Collection<int[]> tuples, boolean markedAsCorrect) {
        Preconditions.check(id > 0, "id must be greater than zero");
        Preconditions.notNull(involvedParameters);
        Preconditions.check(involvedParameters.length > 0, "involved parameters must not be empty");
        Preconditions.notNull(tuples);
        Preconditions.check(!tuples.isEmpty(), "list of tuples must not be empty");
        checkTupleSize(involvedParameters, tuples);

        this.id = id;
        this.involvedParameters = Arrays.copyOf(involvedParameters, involvedParameters.length);
        this.tuples = new ArrayList<>(tuples);
        this.markedAsCorrect = markedAsCorrect;
    }
    
    private static void checkTupleSize(int[] identifier, Collection<int[]> forbiddenTuples) {
        for (int[] forbiddenTuple : forbiddenTuples) {
            Preconditions.check(identifier.length == forbiddenTuple.length);
        }
    }
    
    /**
     * @return the id of the list. Unique to its {@link TestModel}
     */
    public int getId() {
        return id;
    }
    
    /**
     * @return the indices of all parameters involved in the list
     */
    public int[] getInvolvedParameters() {
        return Arrays.copyOf(involvedParameters, involvedParameters.length);
    }
    
    /**
     * @return all tuples which should not be allowed in the format described in {@link TupleList}
     */
    public List<int[]> getTuples() {
        return Collections.unmodifiableList(tuples);
    }

    public boolean isMarkedAsCorrect() {
        return markedAsCorrect;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TupleList tupleList = (TupleList) o;
        return id == tupleList.id &&
                markedAsCorrect == tupleList.markedAsCorrect &&
                Arrays.equals(involvedParameters, tupleList.involvedParameters) &&
                Objects.equals(tuples, tupleList.tuples);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(id, tuples, markedAsCorrect);
        result = 31 * result + Arrays.hashCode(involvedParameters);
        return result;
    }

    @Override
    public String toString() {
        return "TupleList{" +
                "id=" + id +
                ", involvedParameters=" + Arrays.toString(involvedParameters) +
                ", tuples=" + tuples +
                ", markedAsCorrect=" + markedAsCorrect +
                '}';
    }
}
