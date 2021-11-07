package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import org.chocosolver.solver.Model;

import java.util.Objects;
import java.util.function.Function;

public class Constraint {

    private final TupleList tupleList;
    private final Function<Model, org.chocosolver.solver.constraints.Constraint> function;

    public Constraint(TupleList tupleList, Function<Model, org.chocosolver.solver.constraints.Constraint> function) {
        Preconditions.notNull(tupleList);
        Preconditions.notNull(function);

        this.tupleList = tupleList;
        this.function = function;
    }

    Constraint(Constraint other) {
        Preconditions.notNull(other);

        this.tupleList = other.tupleList;
        this.function = other.function;
    }

    public TupleList getTupleList() {
        return tupleList;
    }

    public org.chocosolver.solver.constraints.Constraint apply(final Model model) {
        return function.apply(model);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Constraint that = (Constraint) o;
        return tupleList.equals(that.tupleList) &&
                function.equals(that.function);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tupleList, function);
    }

    @Override
    public String toString() {
        return "ConstraintFunction{" +
                "tupleList=" + tupleList +
                ", function=" + function +
                '}';
    }
}