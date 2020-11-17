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
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ValueConstraints;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import static java.util.Arrays.stream;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 *
 * @author marcel
 */
public class DerivationScope {
    private ModelType baseModel = ModelType.GENERIC;
    private final List<DerivationType> scopeLimits;
    private final List<DerivationType> scopeExtensions;
    private final KeyX keyExchangeRequirements;
    private final List<ValueConstraint> valueConstraints;
    private final ProtocolVersion targetVersion;
    
    public DerivationScope(ExtensionContext context) {
        this.keyExchangeRequirements = (KeyX)KeyX.resolveKexAnnotation(context);
        this.scopeLimits = resolveScopeLimits(context);
        this.scopeExtensions = resolveScopeExtensions(context);
        this.valueConstraints = resolveValueConstraints(context);
        
        TestMethodConfig tmpConfig = new TestMethodConfig(context);
        this.targetVersion = tmpConfig.getTlsVersion().supported();
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
            Arrays.stream(scopeLimitations.value()).forEach(derivation -> limitations.add(derivation));
        }
        return limitations;
    }
    
    private List<DerivationType> resolveScopeExtensions(ExtensionContext context) {
        List<DerivationType> extensions = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ScopeExtensions.class)) {
            ScopeExtensions scopeExtensions = testMethod.getAnnotation(ScopeExtensions.class);
            Arrays.stream(scopeExtensions.value()).forEach(derivation -> extensions.add(derivation));
        }
        return extensions;
    }
    
    private List<ValueConstraint> resolveValueConstraints(ExtensionContext context) {
        List<ValueConstraint> constraints = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if(testMethod.isAnnotationPresent(ValueConstraints.class)) {
            ValueConstraints valConstraints = testMethod.getAnnotation(ValueConstraints.class);
            DerivationType[] affectedTypes = valConstraints.affectedTypes();
            String[] methods = valConstraints.methods();
            if(methods.length != affectedTypes.length) {
                throw new RuntimeException("Unable to resolve ValueConstraints - argument count mismatch");
            }
            for(int i = 0; i < affectedTypes.length; i++) {
                constraints.add(new ValueConstraint(affectedTypes[i], methods[i], context.getRequiredTestClass(), false));
            }
        }
        if(testMethod.isAnnotationPresent(DynamicValueConstraints.class)) {
            DynamicValueConstraints valConstraints = testMethod.getAnnotation(DynamicValueConstraints.class);
            DerivationType[] affectedTypes = valConstraints.affectedTypes();
            String[] methods = valConstraints.methods();
            if(methods.length != affectedTypes.length) {
                throw new RuntimeException("Unable to resolve ValueConstraints - argument count mismatch");
            }
            for(int i = 0; i < affectedTypes.length; i++) {
                constraints.add(new ValueConstraint(affectedTypes[i], methods[i], context.getRequiredTestClass(), true));
            }
        }
        
        return constraints;
    }

    

    public List<ValueConstraint> getValueConstraints() {
        return valueConstraints;
    }

    public ProtocolVersion getTargetVersion() {
        return targetVersion;
    }
}
