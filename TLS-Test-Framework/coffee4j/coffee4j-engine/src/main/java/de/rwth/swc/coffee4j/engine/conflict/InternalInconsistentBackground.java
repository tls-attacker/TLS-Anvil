package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;

public class InternalInconsistentBackground implements InternalExplanation {

    private final int[] background;
    private final int[] relaxable;

    public InternalInconsistentBackground(int[] background, int[] relaxable) {
        Preconditions.notNull(background);
        Preconditions.notNull(relaxable);

        this.background = background;
        this.relaxable = relaxable;
    }

    public int[] getBackground() {
        return background;
    }

    public int[] getRelaxable() {
        return relaxable;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InternalInconsistentBackground that = (InternalInconsistentBackground) o;
        return Arrays.equals(background, that.background) &&
                Arrays.equals(relaxable, that.relaxable);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(background);
        result = 31 * result + Arrays.hashCode(relaxable);
        return result;
    }

    @Override
    public String toString() {
        return "InternalInconsistentBackground{" +
                "background=" + Arrays.toString(background) +
                ", relaxable=" + Arrays.toString(relaxable) +
                '}';
    }
}
