/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import java.util.Arrays;
import static java.util.Arrays.stream;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author marcel
 */
public class DerivationScope {
    private final ModelType baseModel;
    private final List<DerivationType> scopeLimits;
    private final List<DerivationType> scopeExtensions;
    private final KeyX keyExchangeRequirements;

    
    public DerivationScope(ModelType baseModel, DerivationType[] scopeLimits, DerivationType[] scopeExtensions, KeyExchangeType[] supportedKxs, boolean mergeSupportedWithClassSupported, boolean requiresServerKeyExchMsg) {
        this.baseModel = baseModel;
        this.scopeLimits = new LinkedList<>();
        this.scopeExtensions = new LinkedList<>();
        Arrays.stream(scopeLimits).forEach(derivation -> this.scopeLimits.add(derivation));
        Arrays.stream(scopeExtensions).forEach(derivation -> this.scopeExtensions.add(derivation));
        keyExchangeRequirements = new KeyX(supportedKxs, mergeSupportedWithClassSupported, requiresServerKeyExchMsg);
    }

    public ModelType getBaseModel() {
        return baseModel;
    }

    public List<DerivationType> getScopeLimits() {
        return scopeLimits;
    }

    public List<DerivationType> getScopeExtensions() {
        return scopeExtensions;
    }
    
    public void addScopeLimit(DerivationType type) {
        scopeLimits.add(type);
    }
    
    public void addExtension(DerivationType type) {
        scopeExtensions.add(type);
    }
     
    public KeyX getKeyExchangeRequirements() {
        return keyExchangeRequirements;
    }
}
