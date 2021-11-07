package de.rwth.swc.coffee4j.engine.util;

import org.junit.jupiter.api.Test;

import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PredicateUtilTest {
    
    @Test
    void notConvertsNullToNull() {
        assertNull(PredicateUtil.not(null));
    }
    
    @Test
    void convertsPredicate() {
        final Predicate<Boolean> predicate = value -> !value;
        final Predicate<Boolean> negatedPredicate = PredicateUtil.not(predicate);
        
        assertTrue(negatedPredicate.test(true));
        assertFalse(negatedPredicate.test(false));
    }
    
}
