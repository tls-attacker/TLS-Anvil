package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.conflict.choco.ChocoModel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.Objects;

public class InternalConflictSet implements InternalExplanation {

    private final ChocoModel chocoModel;
    private final int[] background;
    private final int[] relaxable;
    private final int[] conflictSet;

    public InternalConflictSet(ChocoModel chocoModel,
                               int[] background,
                               int[] relaxable,
                               int[] conflictSet) {
        Preconditions.notNull(chocoModel);
        Preconditions.notNull(background);
        Preconditions.notNull(relaxable);
        Preconditions.notNull(conflictSet);

        this.chocoModel = chocoModel;
        this.background = background;
        this.relaxable = relaxable;
        this.conflictSet = conflictSet;
    }

    public ChocoModel getChocoModel() {
        return chocoModel;
    }

    public int[] getBackground() {
        return background;
    }

    public int[] getRelaxable() {
        return relaxable;
    }

    public int[] getConflictSet() {
        return conflictSet;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InternalConflictSet that = (InternalConflictSet) o;
        return chocoModel.equals(that.chocoModel) &&
                Arrays.equals(background, that.background) &&
                Arrays.equals(relaxable, that.relaxable) &&
                Arrays.equals(conflictSet, that.conflictSet);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(chocoModel);
        result = 31 * result + Arrays.hashCode(background);
        result = 31 * result + Arrays.hashCode(relaxable);
        result = 31 * result + Arrays.hashCode(conflictSet);
        return result;
    }

    @Override
    public String toString() {
        return "InternalConflictSet{" +
                "chocoModel=" + chocoModel +
                ", background=" + Arrays.toString(background) +
                ", relaxable=" + Arrays.toString(relaxable) +
                ", conflictSet=" + Arrays.toString(conflictSet) +
                '}';
    }
}
