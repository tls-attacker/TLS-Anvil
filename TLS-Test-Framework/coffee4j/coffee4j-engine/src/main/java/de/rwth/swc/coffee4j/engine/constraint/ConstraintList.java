package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

public class ConstraintList {
    private final Collection<TupleList> tupleLists;
    private List<Constraint> constraints;

    public ConstraintList(Collection<TupleList> tupleLists) {
        Preconditions.notNull(tupleLists);

        this.tupleLists = tupleLists;
        this.constraints = null;
    }

    public List<Constraint> getConstraints() {
        if(constraints == null) {
            constraints = new ConstraintConverter().convertAll(tupleLists);
        }

        return constraints;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConstraintList that = (ConstraintList) o;
        return tupleLists.equals(that.tupleLists) &&
                Objects.equals(constraints, that.constraints);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tupleLists, constraints);
    }

    @Override
    public String toString() {
        return "ConstraintList{" +
                '}';
    }
}
