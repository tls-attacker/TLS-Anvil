package de.rwth.swc.coffee4j.engine.conflict.choco;

import org.chocosolver.solver.constraints.Constraint;

import java.util.Arrays;
import java.util.Objects;

class ChocoConstraint {
    private final int id;
    private final Constraint rootConstraint;
    private final Constraint[] allConstraints;
    private ChocoConstraintStatus status;

    ChocoConstraint(int id, Constraint rootConstraint, Constraint[] allConstraints, ChocoConstraintStatus status) {
        this.id = id;
        this.rootConstraint = rootConstraint;
        this.allConstraints = allConstraints;
        this.status = status;
    }

    int getId() {
        return id;
    }

    Constraint getRootConstraint() {
        return rootConstraint;
    }

    Constraint[] getAllConstraints() {
        return allConstraints;
    }

    ChocoConstraintStatus getStatus() {
        return status;
    }

    void setStatus(ChocoConstraintStatus status) {
        this.status = status;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ChocoConstraint that = (ChocoConstraint) o;
        return id == that.id &&
                Arrays.equals(allConstraints, that.allConstraints) &&
                status == that.status;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(id, status);
        result = 31 * result + Arrays.hashCode(allConstraints);
        return result;
    }
}
