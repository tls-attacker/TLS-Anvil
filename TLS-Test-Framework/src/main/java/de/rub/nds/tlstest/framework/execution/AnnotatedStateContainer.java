package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class AnnotatedStateContainer {
    private static final Logger LOGGER = LogManager.getLogger();

    private List<AnnotatedState> states = new ArrayList<>();

    AnnotatedStateContainer(List<AnnotatedState> states) {
        this.states = states;
    }

    public AnnotatedStateContainer() { }

    AnnotatedStateContainer(AnnotatedState... states) {
        this(Arrays.asList(states));
    }


    public void addAll(@Nonnull AnnotatedStateContainer container) {
        this.states.addAll(container.getStates());
    }

    public void addAll(List<AnnotatedState> states) {
        this.states.addAll(states);
    }

    public void addAll(AnnotatedState... states) {
        this.states.addAll(Arrays.asList(states));
    }

    public void add(AnnotatedState state) {
        this.states.add(state);
    }

    public void validate(boolean finalValidation, Consumer<State> f) {
        boolean failed = false;
        List<Throwable> errors = new ArrayList<>();

        for (AnnotatedState i : states) {
            State state = i.getState();
            try {
                state = state.getFinishedFuture().get(0, TimeUnit.MILLISECONDS);
                f.accept(state);
            } catch (Throwable error) {
                failed = true;
                i.setFailedReason(error);
                errors.add(error);
            }
        }

        if (failed && finalValidation) {
           for (Throwable i: errors) {
               LOGGER.error("\n" + ExecptionPrinter.stacktraceToString(i));
           }
           throw new AssertionError("Test failed");
        }
    }

    public void validateFinal(Consumer<State> f) {
        this.validate(true, f);
    }

    public void validate(Consumer<State> f) {
        this.validate(false, f);
    }

    public List<AnnotatedState> getStates() {
        return states;
    }

    public void setStates(List<AnnotatedState> states) {
        this.states = states;
    }
}
