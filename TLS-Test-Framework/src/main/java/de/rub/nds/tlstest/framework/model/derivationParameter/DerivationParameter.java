/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rwth.swc.coffee4j.model.Parameter;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author marcel
 */
public abstract class DerivationParameter<T> {
    
    private final DerivationType type;
    
    private T selectedValue;
    
    public DerivationParameter(DerivationType type) {
        this.type = type;
    }
    
    
    public abstract List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope);
    
    public List<ConditionalConstraint> getConditionalConstraints() {
        return new LinkedList<>();
    }
    
    public Parameter.Builder getParameterBuilder(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = getParameterValues(context, scope);
        return Parameter.parameter(type.name()).values(parameterValues.toArray());
    }
    
    public abstract void applyToConfig(Config config, TestContext context);
    
    public void postProcessConfig(Config config, TestContext context) {
    }
    
    public final T getSelectedValue() {
        return selectedValue;
    }
    
    public final void setSelectedValue(T selectedValue) {
        this.selectedValue = selectedValue;
    }
    
    public DerivationType getType() {
        return type;
    }
    
    public String toString() {
        if(selectedValue instanceof byte[] && selectedValue != null) {
            return type + "=" + ArrayConverter.bytesToHexString((byte[])selectedValue);
        } else {
            return type + "=" + selectedValue;
        }    
    }
}
