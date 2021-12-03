/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import de.rwth.swc.coffee4j.model.Parameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Provides functions to obtain all possible parameter values under a given
 * scope
 */
public abstract class DerivationParameter<T> {
    private static final Logger LOGGER = LogManager.getLogger();

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
        List<DerivationParameter> parameterValues = new LinkedList<>();
        if (scope.hasExplicitValues(type)) { 
            parameterValues = getExplicitValues(scope);
        } else {
            parameterValues = getParameterValues(context, scope).stream().filter(val
                    -> valueApplicableUnderAllConstraints(scope.getValueConstraints(), (T) val.getSelectedValue())
            ).collect(Collectors.toList());
        }
        return parameterValues;
    }

    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        return new LinkedList<>();
    }
    
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        if(scope.hasExplicitModelingConstraints(type)) {
            return getExplicitModelingConstraints(scope);
        } else {
            return getDefaultConditionalConstraints(scope);
        }
    }
    
    public boolean canBeModeled(TestContext context, DerivationScope scope) {
        return getConstrainedParameterValues(context, scope).size() > 1;
    }
    
    public boolean hasNoApplicableValues(TestContext context, DerivationScope scope) {
        return getConstrainedParameterValues(context, scope).isEmpty();
    }
    
    public Parameter.Builder getParameterBuilder(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = getConstrainedParameterValues(context, scope);
        return Parameter.parameter(type.toString()).values(parameterValues.toArray());
    }

    public abstract void applyToConfig(Config config, TestContext context);

    public void postProcessConfig(Config config, TestContext context) {
    }

    public void configureParameterDependencies(Config config, TestContext context, DerivationContainer container){
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
        for (ValueConstraint constraint : valueConstraints) {
            if (constraint.getAffectedType() == type) {
                if (!valueApplicableUnderConstraint(constraint, valueInQuestion)) {
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
            if (valueConstraint.isDynamic()) {
                method = valueConstraint.getClazz().getMethod(valueConstraint.getEvaluationMethod(), valueClass);
                constructor = valueConstraint.getClazz().getConstructor();
                return (Boolean) method.invoke(constructor.newInstance(), valueInQuestion);
            } else {
                method = valueClass.getMethod(valueConstraint.getEvaluationMethod());
                return (Boolean) method.invoke(valueInQuestion);
            }
        } catch (InstantiationException | SecurityException | NoSuchMethodException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            LOGGER.error("Was unable to invoke constraint method for type " + type, ex);
            return true;
        }
    }

    public List<DerivationParameter> getExplicitValues(DerivationScope scope) {
        try {
            String methodName = scope.getExplicitValueMethod(type);
            Method method = scope.getExtensionContext().getRequiredTestClass().getMethod(methodName, DerivationScope.class);
            Constructor constructor = scope.getExtensionContext().getRequiredTestClass().getConstructor();

            return (List<DerivationParameter>) method.invoke(constructor.newInstance(), scope);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalArgumentException | IllegalAccessException | InstantiationException ex) {
            LOGGER.error("Was unable to fetch explicit values for type " + type, ex); 
            return new LinkedList<>();
        }
    }
    
    public List<ConditionalConstraint> getExplicitModelingConstraints(DerivationScope scope) {
        try {
            String methodName = scope.getExplicitModelingConstraintMethod(type);
            Method method = scope.getExtensionContext().getRequiredTestClass().getMethod(methodName, DerivationScope.class);
            Constructor constructor = scope.getExtensionContext().getRequiredTestClass().getConstructor();

            return (List<ConditionalConstraint>) method.invoke(constructor.newInstance(), scope);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalArgumentException | IllegalAccessException | InstantiationException ex) {
            LOGGER.error("Was unable to fetch explicit constraints for type " + type, ex);
            return new LinkedList<>();
        }
    }

    public String toString() {
        return type + "=" + jsonValue();
    }

    public DerivationType getParent() {
        return parent;
    }

    public void setParent(DerivationType parent) {
        this.parent = parent;
    }

    @JsonValue
    public String jsonValue() {
        if (selectedValue instanceof byte[]) {
            return ArrayConverter.bytesToHexString((byte[]) selectedValue);
        } else {
            return "" + selectedValue;
        }
    }
}
