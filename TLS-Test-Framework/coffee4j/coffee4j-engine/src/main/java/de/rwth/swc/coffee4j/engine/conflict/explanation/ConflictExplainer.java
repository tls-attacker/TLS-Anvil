package de.rwth.swc.coffee4j.engine.conflict.explanation;

import de.rwth.swc.coffee4j.engine.conflict.InternalExplanation;
import de.rwth.swc.coffee4j.engine.conflict.choco.ChocoModel;

import java.util.Optional;

public interface ConflictExplainer {

    Optional<InternalExplanation> getMinimalConflict(ChocoModel model, int[] background, int[] relaxable);
}
