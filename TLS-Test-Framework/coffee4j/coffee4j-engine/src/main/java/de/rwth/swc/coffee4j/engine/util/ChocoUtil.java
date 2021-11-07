package de.rwth.swc.coffee4j.engine.util;

import org.chocosolver.solver.Model;
import org.chocosolver.solver.variables.Variable;

import java.util.Arrays;
import java.util.Optional;

public final class ChocoUtil {

    private ChocoUtil() {
    }

    /**
     * Searches for a variable with a given id as its name
     * @param model ChocoSolver model
     * @param id    id that represents the name of the variable
     * @return      optional that contains the variable if found
     */
    public static Optional<Variable> findVariable(final Model model, int id) {
        Preconditions.notNull(model);
        Preconditions.check(id >= 0);

        final String name = String.valueOf(id);

        return Arrays.stream(model.getVars())
                .filter(variable -> variable.getName().equals(name))
                .findFirst();
    }
}
