package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;

public class WorkflowRunner {

    private TestContext context = null;

    private KeyExchange keyExchange = null;


    public WorkflowRunner(TestContext context) {
        this.context = context;
    }


    public void execute(WorkflowTrace trace, Config config) {

    }

    public void execute(WorkflowTrace trace) {
        this.execute(trace, this.context.getConfig().createConfig());
    }

    public KeyExchange getKeyExchange() {
        return keyExchange;
    }

    public void setKeyExchange(KeyExchange keyExchange) {
        this.keyExchange = keyExchange;
    }
}
