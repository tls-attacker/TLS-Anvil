package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.utils.Utils;
import de.rwth.swc.coffee4j.model.Combination;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Queue;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A special {@link Iterator} since streaming a java {@link Queue} directly does not allow
 * concurrent modification of said queue. In our case this means that one cannot add test inputs to
 * the execution queue while executing elements from the queue. Consequently, it is not possible to
 * add fault characterization test inputs. Therefore, this iterator decouples the actual queue from
 * the stream by having and internal queue and only allowing access through well defined public
 * methods. This iterator is NOT thread-safe and should not be used with parallel test execution in
 * junit-jupiter!
 */
class TestInputIterator implements Iterator<Combination> {

    private final BlockingDeque<Combination> testInputQueue = new LinkedBlockingDeque<>();
    private final ExtensionContext extensionContext;

    synchronized void add(Combination testInput) {
        testInputQueue.add(testInput);
    }

    public TestInputIterator(ExtensionContext context) {
        extensionContext = context;
    }

    @Override
    public boolean hasNext() {
        String uniqueId =
                Utils.getTemplateContainerExtensionContext(extensionContext).getUniqueId();
        while (!TestContext.getInstance().testIsFinished(uniqueId)) {
            try {
                Combination nextTestInput = testInputQueue.poll(3, TimeUnit.SECONDS);
                if (nextTestInput != null) {
                    testInputQueue.addFirst(nextTestInput);
                    return true;
                }
            } catch (InterruptedException ignored) {
            }
        }

        return false;
    }

    @Override
    public Combination next() {
        final Combination nextTestInput = testInputQueue.poll();

        if (nextTestInput == null) {
            throw new NoSuchElementException("No more elements in iterator");
        }

        return nextTestInput;
    }

    public BlockingQueue<Combination> getTestInputQueue() {
        return testInputQueue;
    }
}
