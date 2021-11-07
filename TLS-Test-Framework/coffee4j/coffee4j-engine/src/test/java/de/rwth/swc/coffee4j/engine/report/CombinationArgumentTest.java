package de.rwth.swc.coffee4j.engine.report;

import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CombinationArgumentTest {

    @Test
    void preconditions() {
        assertThrows(NullPointerException.class, () -> new CombinationArgument(null));
    }

    @Test
    void argument() {
        final int[] combination = new int[]{1, CombinationUtil.NO_VALUE, 2};
        final CombinationArgument firstArgument = new CombinationArgument(combination);
        final CombinationArgument secondArgument = CombinationArgument.combination(combination);

        assertArrayEquals(combination, firstArgument.getCombination());
        assertArrayEquals(combination, secondArgument.getCombination());
    }

}
