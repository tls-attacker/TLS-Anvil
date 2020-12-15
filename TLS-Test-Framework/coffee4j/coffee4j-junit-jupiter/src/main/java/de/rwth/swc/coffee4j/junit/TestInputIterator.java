package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.model.Combination;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Queue;

/**
 * A special {@link Iterator} since streaming a java {@link Queue} directly does not allow concurrent modification
 * of said queue. In our case this means that one cannot add test inputs to the execution queue while executing
 * elements from the queue. Consequently, it is not possible to add fault characterization test inputs.
 * Therefore, this iterator decouples the actual queue from the stream by having and internal queue and only allowing
 * access through well defined public methods.
 * This iterator is NOT thread-safe and should not be used with parallel test execution in junit-jupiter!
 */
class TestInputIterator implements Iterator<Combination> {
    
    private final Queue<Combination> testInputQueue = new LinkedList<>();
    
    void add(Combination testInput) {
        testInputQueue.add(testInput);
    }
    
    @Override
    public boolean hasNext() {
        return !testInputQueue.isEmpty();
    }
    
    @Override
    public Combination next() {
        final Combination nextTestInput = testInputQueue.poll();
        
        if (nextTestInput == null) {
            throw new NoSuchElementException("No more elements in iterator");
        }
        
        return nextTestInput;
    }
    
}
