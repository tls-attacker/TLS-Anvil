package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;

/**
 * Some {@link ArgumentConverter} need a {@link ModelConverter} so that they can convert internal representations
 * to external representations. This class handles the initialization of said converter.
 */
public abstract class ModelBasedArgumentConverter implements ArgumentConverter {
    
    protected ModelConverter modelConverter;
    
    /**
     * Initializes the testModel converter to be used by the implementing class.
     *
     * @param modelConverter the testModel converter used for arguments. Must not be {@code null}
     */
    public void initialize(ModelConverter modelConverter) {
        this.modelConverter = Preconditions.notNull(modelConverter);
    }
    
}
