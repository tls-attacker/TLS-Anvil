package de.rwth.swc.coffee4j.engine.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class PreconditionsTest {
    
    @Test
    void checkNotNullThrowsExceptionIfNull() {
        assertThrows(NullPointerException.class, () -> Preconditions.notNull(null));
    }
    
    @Test
    void checkNotNullExceptionHasGivenMessage() {
        final Throwable throwable = assertThrows(NullPointerException.class, () -> Preconditions.notNull(null, "test"));
        assertEquals("test", throwable.getMessage());
    }
    
    @Test
    void checkNotNullEvaluatesSupplier() {
        final Throwable throwable = assertThrows(NullPointerException.class, () -> Preconditions.notNull(null, () -> "test"));
        assertEquals("test", throwable.getMessage());
    }
    
    @Test
    @SuppressWarnings("ObviousNullCheck")
    void resultIsReturnedIfNotNull() {
        assertEquals("test", Preconditions.notNull("test"));
    }
    
    @Test
    void checkThrowsExceptionIfFalse() {
        assertThrows(IllegalArgumentException.class, () -> Preconditions.check(false));
    }
    
    @Test
    void checkThrowsExceptionWithGivenMessageIfFalse() {
        final Throwable throwable = assertThrows(IllegalArgumentException.class, () -> Preconditions.check(false, "test"));
        assertEquals("test", throwable.getMessage());
    }
    
    @Test
    void checkEvaluatesSupplier() {
        final Throwable throwable = assertThrows(IllegalArgumentException.class, () -> Preconditions.check(false, () -> "test"));
        assertEquals("test", throwable.getMessage());
    }
    
    @Test
    void checkDoesNotThrowExceptionIfTrue() {
        Preconditions.check(true);
    }
    
    @Test
    void doesNotContainNullThrowsIfCollectionContainsOneNullElement() {
        assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Collections.singletonList(null)));
        assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Collections.singleton(null)));
        assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Arrays.asList("test", null, "test")));
        assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Arrays.asList(null, "test")));
        assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Arrays.asList("test", null)));
    }
    
    @Test
    void doesNotContainNullThrowsCorrectMessageIfContainsNull() {
        final Throwable throwable = assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Arrays.asList(null, "test"), "testMessage"));
        assertEquals("testMessage", throwable.getMessage());
    }
    
    @Test
    void doesNotContainNullThrowsCorrectSuppliedMessageIfContainsNull() {
        final Throwable throwable = assertThrows(IllegalArgumentException.class, () -> Preconditions.doesNotContainNull(Collections.singleton(null), () -> "testMessage"));
        assertEquals("testMessage", throwable.getMessage());
    }
    
    @ParameterizedTest
    @MethodSource
    void doesNotContainNullReturnsCollectionIfDoesNotContainNull(Collection<?> testedCollection) {
        assertEquals(testedCollection, Preconditions.doesNotContainNull(testedCollection));
    }
    
    @SuppressWarnings("unused")
    private static Stream<Arguments> doesNotContainNullReturnsCollectionIfDoesNotContainNull() {
        return Stream.of(arguments(Collections.emptyList()), arguments(Collections.emptySet()), arguments(Collections.singleton("test")), arguments(Collections.singletonList(Optional.empty())), arguments(Arrays.asList("test1", "test2")));
    }
    
}
