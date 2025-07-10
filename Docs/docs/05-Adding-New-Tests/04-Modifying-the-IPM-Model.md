import JavaClass from "@site/src/components/JavaClass"
import Definition from "@site/src/components/Definition"

# Modifying the IPM

As described earlier, TLS-Anvil defines four common IPMs. Occasionally, different parameters and/or parameter values need to be included in the IPM. To support this, the Anvil-Core-Framework provides several test template annotations that allow modification of a selected base IPM. These annotations are explained below.

## Modifying Parameters

### `IncludeParameter`

Accepts a string corresponding to the enum value of `TlsParameterType` for the parameter to be added to the base IPM. The values for the parameter are automatically derived from the features supported by the <Definition id="SUT"/> as well as general constraints.

### `ExcludeParameter`

Accepts a string corresponding to the enum value of `TlsParameterType` for the parameter to be removed from the base IPM.

## Modifying Parameter Values

### `DynamicValueConstraints`

```java
public @interface DynamicValueConstraints {
    Class<?> clazz() default Object.class;
    String[] affectedIdentifiers();
    String[] methods();
}
```

Each method listed in the `methods` array is invoked with the chosen parameter value of the parameter defined at the corresponding index of the `affectedIdentifiers` array. If no `clazz` is specified, the method is called via reflection on the same class as the test template.

The method should return a `boolean` value. If the return value is `true`, the combination of parameter values is considered valid test input; otherwise, the test input is skipped.

### `ValueConstraint`

```java
public @interface ValueConstraints {
    DerivationType identifier();
    String method();
}
```

Some parameter values are based on TLS-Attacker enums, e.g., <JavaClass path="TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/model/derivationParameter/CipherSuiteDerivation.java" />. These enums already include methods that return a `boolean` indicating whether the enum value fulfills certain criteria.

The method specified in the `method` field is called via reflection on the selected enum corresponding to the `identifier`. If the method returns `true`, the parameter combination is considered valid test input; otherwise, the test input is skipped.

### `ExplicitValues`

```java
public @interface ExplicitValues {
    Class<?> clazz() default Object.class;
    String[] affectedIdentifiers();
    String[] methods();
}
```

In some cases, explicit values should be considered as parameter values regardless of the features supported by the <Definition id="SUT"/>. This annotation assigns such explicit values to parameters.

The methods specified in the `methods` array are invoked via reflection on `clazz` (the test template class by default). Each method should return a `List<DerivationParameter>`.

### `ExplicitModelingConstraints`

```java
public @interface ExplicitModelingConstraints {
    Class<?> clazz() default Object.class;
    String[] affectedIdentifiers();
    String[] methods();
}
```

This annotation replaces the default constraints for parameters with explicitly defined constraints. Each method in the `methods` array should return a list of <JavaClass path="TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/model/constraint/ConditionalConstraint.java" /> instances to be applied to the parameter at the corresponding index of the `affectedIdentifiers` array.
