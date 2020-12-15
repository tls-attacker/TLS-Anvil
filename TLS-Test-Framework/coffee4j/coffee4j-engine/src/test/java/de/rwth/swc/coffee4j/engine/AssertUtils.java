package de.rwth.swc.coffee4j.engine;

import static org.junit.jupiter.api.Assertions.fail;

public class AssertUtils {

    public static void assertInstanceOf(Class<?> clazz, Object object) {
        if(!clazz.isInstance(object)) {
            fail("expected object of class " + clazz);
        }
    }
}
