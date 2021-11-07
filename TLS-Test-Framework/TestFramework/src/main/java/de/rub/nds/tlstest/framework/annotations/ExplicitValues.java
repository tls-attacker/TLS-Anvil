package de.rub.nds.tlstest.framework.annotations;

import de.rub.nds.tlstest.framework.model.DerivationType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface ExplicitValues {
    Class<?> clazz() default Object.class;
    DerivationType[] affectedTypes();
    String[] methods();
}
