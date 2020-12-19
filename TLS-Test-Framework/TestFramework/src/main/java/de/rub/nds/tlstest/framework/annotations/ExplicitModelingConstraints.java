package de.rub.nds.tlstest.framework.annotations;

import de.rub.nds.tlstest.framework.model.DerivationType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation provides the interface to define methods for
 * DerivationTypes to set specific Coffee4j constraints
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface ExplicitModelingConstraints {
    Class<?> clazz() default Object.class;
    DerivationType[] affectedTypes();
    String[] methods();
}