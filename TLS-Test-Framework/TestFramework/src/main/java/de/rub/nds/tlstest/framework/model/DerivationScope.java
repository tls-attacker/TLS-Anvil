/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ValueConstraints;
import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import static java.util.Arrays.stream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.extension.ExtensionContext;
import de.rub.nds.tlstest.framework.annotations.ExplicitModelingConstraints;
import de.rub.nds.tlstest.framework.annotations.TestStrength;

/**
 * Defines which TLS parameters are used for the test derivation and how they
 * are applied to the session.
 */
public class DerivationScope {
    private ModelType baseModel = ModelType.GENERIC;
    private final List<DerivationType> scopeLimits;
    private final List<DerivationType> scopeExtensions;
    private final KeyX keyExchangeRequirements;
    private final List<ValueConstraint> valueConstraints;
    private final Map<DerivationType, String> explicitValues;
    private final Map<DerivationType, String> explicitModelingConstraints;
    private final ExtensionContext extensionContext;
    private final Set<DerivationType> manualConfigTypes;
    private final int testStrength;
  
    public DerivationScope(ExtensionContext context) {
        this.keyExchangeRequirements = (KeyX)KeyX.resolveKexAnnotation(context);
        this.scopeLimits = resolveScopeLimits(context);
        this.scopeExtensions = resolveScopeExtensions(context);
        this.valueConstraints = resolveValueConstraints(context);
        this.explicitValues = resolveExplicitValues(context);
        this.explicitModelingConstraints = resolveExplicitModelingConstraints(context);
        this.manualConfigTypes = resolveManualConfigTypes(context);
        this.extensionContext = context;
        this.testStrength = resolveTestStrength(context);
    }
    
    public DerivationScope(ExtensionContext context, ModelFromScope modelFromScope) {
        this(context); 
        this.baseModel = modelFromScope.baseModel();
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
    
    private List<DerivationType> resolveScopeLimits(ExtensionContext context) {
        List<DerivationType> limitations = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ScopeLimitations.class)) {
            ScopeLimitations scopeLimitations = testMethod.getAnnotation(ScopeLimitations.class);
            for(String typeStr : scopeLimitations.value()){
                DerivationType derivationType;
                try{
                    derivationType = DerivationManager.getInstance().getDerivationFromString(typeStr);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                limitations.add(derivationType);
            }
        }
        return limitations;
    }
    
    private List<DerivationType> resolveScopeExtensions(ExtensionContext context) {
        List<DerivationType> extensions = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ScopeExtensions.class)) {
            ScopeExtensions scopeExtensions = testMethod.getAnnotation(ScopeExtensions.class);
            for(String typeStr : scopeExtensions.value()){
                DerivationType derivationType;
                try{
                    derivationType = DerivationManager.getInstance().getDerivationFromString(typeStr);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                extensions.add(derivationType);
            }
        }
        return extensions;
    }
    
    private List<ValueConstraint> resolveValueConstraints(ExtensionContext context) {
        List<ValueConstraint> constraints = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ValueConstraints.class)) {
            ValueConstraints valConstraints = testMethod.getAnnotation(ValueConstraints.class);
            String[] affectedTypes = valConstraints.affectedTypes();
            String[] methods = valConstraints.methods();
            if(methods.length != affectedTypes.length) {
                throw new RuntimeException("Unable to resolve ValueConstraints - argument count mismatch");
            }
            for(int i = 0; i < affectedTypes.length; i++) {
                DerivationType affectedType;
                try{
                    affectedType = DerivationManager.getInstance().getDerivationFromString(affectedTypes[i]);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                constraints.add(new ValueConstraint(affectedType, methods[i], context.getRequiredTestClass(), false));
            }
        }
        if(testMethod.isAnnotationPresent(DynamicValueConstraints.class)) {
            DynamicValueConstraints valConstraints = testMethod.getAnnotation(DynamicValueConstraints.class);
            String[] affectedTypes = valConstraints.affectedTypes();
            String[] methods = valConstraints.methods();
            if(methods.length != affectedTypes.length) {
                throw new RuntimeException("Unable to resolve ValueConstraints - argument count mismatch");
            }
            for(int i = 0; i < affectedTypes.length; i++) {
                DerivationType affectedType;
                try{
                    affectedType = DerivationManager.getInstance().getDerivationFromString(affectedTypes[i]);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                constraints.add(new ValueConstraint(affectedType, methods[i], context.getRequiredTestClass(), true));
            }
        }
        
        return constraints;
    }

    private Map<DerivationType, String> resolveExplicitValues(ExtensionContext context) {
        Map<DerivationType, String> valueMap = new HashMap<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ExplicitValues.class)) {
            ExplicitValues explicitValues = testMethod.getAnnotation(ExplicitValues.class);
            String[] affectedTypes = explicitValues.affectedTypes();
            String[] methods = explicitValues.methods();
            if(methods.length != affectedTypes.length) {
                throw new RuntimeException("Unable to resolve ExplicitValues - argument count mismatch");
            }
            for(int i = 0; i < affectedTypes.length; i++) {
                DerivationType affectedType;
                try{
                    affectedType = DerivationManager.getInstance().getDerivationFromString(affectedTypes[i]);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                if(valueMap.containsKey(affectedType)) {
                    throw new RuntimeException("Unable to resolve ExplicitValues - multiple explicit values derfined for " + affectedTypes[i]);
                }
                valueMap.put(affectedType, methods[i]);
            }
        }
        return valueMap;
    }
    
    private Map<DerivationType, String> resolveExplicitModelingConstraints(ExtensionContext context) {
        Map<DerivationType, String> valueMap = new HashMap<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ExplicitModelingConstraints.class)) {
            ExplicitModelingConstraints explicitConstraints = testMethod.getAnnotation(ExplicitModelingConstraints.class);
            String[] affectedTypes = explicitConstraints.affectedTypes();
            String[] methods = explicitConstraints.methods();
            if(methods.length != affectedTypes.length) {
                throw new RuntimeException("Unable to resolve ExplicitModelParameterConstraints - argument count mismatch");
            }
            for(int i = 0; i < affectedTypes.length; i++) {
                DerivationType affectedType;
                try{
                    affectedType = DerivationManager.getInstance().getDerivationFromString(affectedTypes[i]);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                if(valueMap.containsKey(affectedType)) {
                    throw new RuntimeException("Unable to resolve ExplicitModelParameterConstraints - multiple explicit values defined for " + affectedTypes[i]);
                }
                valueMap.put(affectedType, methods[i]);
            }
        }
        return valueMap;
    }
    
    private Set<DerivationType> resolveManualConfigTypes(ExtensionContext context) {
        Set<DerivationType> manualConfigTypes = new HashSet<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ManualConfig.class)) {
            ManualConfig manualConfig = testMethod.getAnnotation(ManualConfig.class);
            String[] types = manualConfig.value();
            for(String typeStr : types){
                DerivationType derivationType;
                try{
                    derivationType = DerivationManager.getInstance().getDerivationFromString(typeStr);
                }
                catch(UnsupportedOperationException e){
                    // If the respective DerivationType enum is not registered this type is simply skipped.
                    continue;
                }
                manualConfigTypes.add(derivationType);
            }
        }
        return manualConfigTypes;
    }
    
    private int resolveTestStrength(ExtensionContext context) {
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(TestStrength.class)) {
            TestStrength testStrength = testMethod.getAnnotation(TestStrength.class); 
            return testStrength.value();
        }
        return TestContext.getInstance().getConfig().getStrength();
    }
    
    public boolean hasExplicitValues(DerivationType type) {
        return explicitValues.containsKey(type);
    }
    
    public boolean hasExplicitModelingConstraints(DerivationType type) {
        return explicitModelingConstraints.containsKey(type);
    }

    public List<ValueConstraint> getValueConstraints() {
        return valueConstraints;
    }

    public ProtocolVersion getTargetVersion() {
        if(isTls13Test()) {
            return ProtocolVersion.TLS13;
        } else {
            return ProtocolVersion.TLS12;
        }
    }

    public String getExplicitValueMethod(DerivationType type) {
        return explicitValues.get(type);
    }
    
    public String getExplicitModelingConstraintMethod(DerivationType type) {
        return explicitModelingConstraints.get(type);
    }

    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }
    
    public boolean isTls13Test() {
        /* Some tests defined in TLS 1.3 test packages
         * test the backwards compatibility of an implementation
         * using a TLS 1.2 handshake - this is evident from the defined
         * KeyExchange annotation
        */ 
        return keyExchangeRequirements.supports(KeyExchangeType.ALL13);
    }
       
    public boolean isAutoApplyToConfig(DerivationType type) {
        return !manualConfigTypes.contains(type);
    }

    public Map<DerivationType, String> getExplicitTypeValues() {
        return explicitValues;
    }

    public int getTestStrength() {
        return testStrength;
    }
    
}
