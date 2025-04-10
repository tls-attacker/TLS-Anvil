/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.ITask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;

public class ParallelExecutorWithTimeout extends ParallelExecutor {

    private final long timeoutAfter;

    public ParallelExecutorWithTimeout(int size, int reexecutions, long timeoutSec) {
        super(
                size,
                reexecutions,
                new ThreadPoolExecutor(
                        size, size, 10L, TimeUnit.DAYS, new LinkedBlockingDeque<>()));
        this.timeoutAfter = timeoutSec;
    }

    @Override
    public void bulkExecuteStateTasks(Iterable<State> stateList) {
        List<Future<ITask>> futureList = new LinkedList<>();
        for (State state : stateList) {
            futureList.add(addStateTask(state));
        }
        for (Future<ITask> future : futureList) {
            try {
                future.get(timeoutAfter, TimeUnit.SECONDS);
            } catch (TimeoutException ex) {
                throw new RuntimeException(
                        String.format(
                                "Failed to execute task! Timed out after %d sec.", timeoutAfter),
                        ex);
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
    }

    @Override
    public List<ITask> bulkExecuteTasks(Iterable<TlsTask> taskList) {
        List<Future<ITask>> futureList = new LinkedList<>();
        List<ITask> resultList = new ArrayList<>(0);
        for (TlsTask tlStask : taskList) {
            futureList.add(addTask(tlStask));
        }
        for (Future<ITask> future : futureList) {
            try {
                ITask res = future.get(timeoutAfter, TimeUnit.SECONDS);
                resultList.add(res);
            } catch (TimeoutException ex) {
                throw new RuntimeException(
                        String.format(
                                "Failed to execute task! Timed out after %d sec.", timeoutAfter),
                        ex);
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
        return resultList;
    }
}
