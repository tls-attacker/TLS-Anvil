/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;

import java.util.List;

public class InboundConnectionWithCustomTriggerArgs extends InboundConnection {
    List<String> triggerArgs;

    public InboundConnectionWithCustomTriggerArgs(InboundConnection other){
        super(other);
    }

    public InboundConnectionWithCustomTriggerArgs(InboundConnection other, List<String> triggerArgs){
        super(other);
        this.triggerArgs = triggerArgs;
    }

    public List<String> getTriggerArgs() {
        return triggerArgs;
    }

    public void setTriggerArgs(List<String> triggerArgs) {
        this.triggerArgs = triggerArgs;
    }



}
