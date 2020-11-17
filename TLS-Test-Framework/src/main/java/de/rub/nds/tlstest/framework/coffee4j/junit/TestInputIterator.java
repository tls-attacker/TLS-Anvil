package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rwth.swc.coffee4j.model.Combination;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Queue;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

/**
 * A special {@link Iterator} since streaming a java {@link Queue} directly does not allow concurrent modification
 * of said queue. In our case this means that one cannot add test inputs to the execution queue while executing
 * elements from the queue. Consequently, it is not possible to add fault characterization test inputs.
 * Therefore, this iterator decouples the actual queue from the stream by having and internal queue and only allowing
 * access through well defined public methods.
 * This iterator is NOT thread-safe and should not be used with parallel test execution in junit-jupiter!
 */
class TestInputIterator implements Iterator<Combination> {
    
    private final BlockingDeque<Combination> testInputQueue = new LinkedBlockingDeque<>();
    
    void add(Combination testInput) {
        testInputQueue.add(testInput);
    }
    
    @Override
    public boolean hasNext() {
        try {
            Combination nextTestInput = testInputQueue.poll(10, TimeUnit.SECONDS);
            if (nextTestInput != null)
                testInputQueue.addFirst(nextTestInput);
            return nextTestInput != null;
        } catch (InterruptedException e) {
            return false;
        }
    }
    
    @Override
    public Combination next() {
        final Combination nextTestInput;
        try {
            nextTestInput = testInputQueue.poll(1, TimeUnit.DAYS);

            if (nextTestInput == null) {
                throw new NoSuchElementException("No more elements in iterator");
            }

            return nextTestInput;

        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return null;
    }

    public BlockingQueue<Combination> getTestInputQueue() {
        return testInputQueue;
    }
}
