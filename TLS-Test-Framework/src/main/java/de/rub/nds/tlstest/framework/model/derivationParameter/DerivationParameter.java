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
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import de.rwth.swc.coffee4j.model.Parameter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 *
 * @author marcel
 */
public abstract class DerivationParameter<T> {
    
    private final DerivationType type;
    
    private T selectedValue;
    
    private DerivationType parent = null;
    
    private final Class<T> valueClass;
    
    public DerivationParameter(DerivationType type, Class<T> valueClass) {
        this.type = type;
        this.valueClass = valueClass;
    }
    
    
    public abstract List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope);
    
    public List<DerivationParameter> getConstrainedParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = getParameterValues(context, scope);
        parameterValues = parameterValues.stream().filter(val -> 
            valueApplicableUnderAllConstraints(scope.getValueConstraints(), (T)val.getSelectedValue())
        ).collect(Collectors.toList());
        return parameterValues;
    }
    
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        return new LinkedList<>();
    }
    
    public Parameter.Builder getParameterBuilder(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = getConstrainedParameterValues(context, scope);
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
    
    public boolean valueApplicableUnderAllConstraints(List<ValueConstraint> valueConstraints, T valueInQuestion) {
        for(ValueConstraint constraint : valueConstraints) {
            if(constraint.getAffectedType() == type) {
                if(!valueApplicableUnderConstraint(constraint, valueInQuestion)) {
                    return false;
                }
            }
        }
        return true;
    }
    
    public boolean valueApplicableUnderConstraint(ValueConstraint valueConstraint, T valueInQuestion) {
        try {
            Method method; 
            Constructor constructor;
            if(valueConstraint.isDynamic()) {
                method = valueConstraint.getClazz().getMethod(valueConstraint.getEvaluationMethod(), valueClass);
                constructor = valueConstraint.getClazz().getConstructor();
                return (Boolean)method.invoke(constructor.newInstance(), valueInQuestion);
            } else {
                method = valueClass.getMethod(valueConstraint.getEvaluationMethod());
                return (Boolean)method.invoke(valueInQuestion);
            }
        } catch (InstantiationException | SecurityException | NoSuchMethodException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            Logger.getLogger(DerivationParameter.class.getName()).log(Level.SEVERE, null, ex);
            return true;
        }
    }
    
    public String toString() {
        if(selectedValue instanceof byte[] && selectedValue != null) {
            return type + "=" + ArrayConverter.bytesToHexString((byte[])selectedValue);
        } else {
            return type + "=" + selectedValue;
        }    
    }

    /**
     * @return the parent
     */
    public DerivationType getParent() {
        return parent;
    }

    /**
     * @param parent the parent to set
     */
    public void setParent(DerivationType parent) {
        this.parent = parent;
    }
}
