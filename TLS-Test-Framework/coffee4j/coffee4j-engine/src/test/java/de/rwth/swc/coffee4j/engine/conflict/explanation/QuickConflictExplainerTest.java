package de.rwth.swc.coffee4j.engine.conflict.explanation;

import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;
import de.rwth.swc.coffee4j.engine.conflict.InternalExplanation;
import de.rwth.swc.coffee4j.engine.conflict.InternalInconsistentBackground;
import de.rwth.swc.coffee4j.engine.conflict.choco.ChocoModel;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static de.rwth.swc.coffee4j.engine.conflict.choco.ChocoModelTest.createTestModel;
import static org.junit.jupiter.api.Assertions.*;

class QuickConflictExplainerTest {

    @Test
    void testExplicitConflict() {
        final ChocoModel chocoModel = createTestModel(4);
        chocoModel.setAssignmentConstraint(new int[] { 0, 1 }, new int[] { 0, 2 });

        final int[] background = { 4, 6 };

        Optional<InternalExplanation> explanation;

        explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 2, 3, 5 });

        assertTrue(explanation.isPresent());
        assertTrue(explanation.get() instanceof InternalConflictSet);
        assertArrayEquals(new int[]{2}, ((InternalConflictSet) explanation.get()).getConflictSet());
        assertTrue(chocoModel.allConstraintsEnabled());

        explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 3, 5 });
        assertFalse(explanation.isPresent());
        assertTrue(chocoModel.allConstraintsEnabled());
    }

    @Test
    void testImplicitConflict() {
        final ChocoModel chocoModel = createTestModel(2);
        chocoModel.setAssignmentConstraint(new int[] { 1 }, new int[] { 2 });

        final int[] background = { 2, 6 };

        Optional<InternalExplanation> explanation;

        explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 3, 4, 5 });
        assertTrue(explanation.isPresent());
        assertTrue(explanation.get() instanceof InternalConflictSet);
        assertArrayEquals(new int[]{1, 4, 5}, ((InternalConflictSet) explanation.get()).getConflictSet());
        assertTrue(chocoModel.allConstraintsEnabled());

        explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 3, 4, 5 });
        assertFalse(explanation.isPresent());
        assertTrue(chocoModel.allConstraintsEnabled());

        explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 3, 5 });
        assertFalse(explanation.isPresent());
        assertTrue(chocoModel.allConstraintsEnabled());

        explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 3, 4 });
        assertFalse(explanation.isPresent());
        assertTrue(chocoModel.allConstraintsEnabled());
    }

    @Test
    void testNoConflict() {
        final ChocoModel chocoModel = createTestModel(4);
        chocoModel.setAssignmentConstraint(new int[] { 0 }, new int[] { 0 });

        final int[] background = { 4, 6 };

        final Optional<InternalExplanation> explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 2, 3, 5 });
        assertFalse(explanation.isPresent());
        assertTrue(chocoModel.allConstraintsEnabled());
    }

    @Test
    void testInconsistentBackgroundConflict() {
        final ChocoModel chocoModel = createTestModel(4);
        chocoModel.setAssignmentConstraint(new int[] { 0, 1 }, new int[] { 0, 2 });

        final int[] background = { 2, 4, 6 }; /* 2 is marked as correct */

        final Optional<InternalExplanation> explanation = new QuickConflictExplainer()
                .getMinimalConflict(chocoModel, background, new int[] { 1, 3, 5 });

        assertTrue(explanation.isPresent());
        assertTrue(explanation.get() instanceof InternalInconsistentBackground);
        assertTrue(chocoModel.allConstraintsEnabled());
    }
}
