import JavaClass from "@site/src/components/JavaClass"
import Definition from "@site/src/components/Definition"

# Modifying the IPM

As described before, TLS-Anvil defines 4 common IPMs. Sometimes different parameters and/or parameter values should be part of the IPM. Therefore, TLS-Anvil provides several test template annotations that allow to modify a selected base IPM. Those are explained in the following.

## Modifying Parameters
### `ScopeExtensions`
Takes a `DerivationType` enum object for the parameter that should be added to the base IPM. The values for the parameter are derived automatically from the features that the <Definition id="SUT"/> supports as well as the general constraints.

### `ScopeLimitations`
Takes a `DerivationType` enum object for the parameter that should be removed from the base IPM.

## Modifying Parameter Values
### `DynamicValueConstraints`
```java
public @interface DynamicValueConstraints {
    Class<?> clazz() default Object.class;
    DerivationType[] affectedTypes();
    String[] methods();
}
```
Each method of the `methods` array is called with the chosen parameter value of the parameter defined at the same index of the `affectedTypes` array. When no `clazz` is specified, the method is called using reflection on the same class as the test template. 

The method should return a `boolean` value. If the return value is `true`, the combination of parameter values is considered as valid test input. Otherwise the test input is skipped.


### `ValueConstraints`
```java
public @interface ValueConstraints {
    DerivationType[] affectedTypes();
    String[] methods();
}
```
Some parameter values are based on TLS-Attacker enums, e.g. <JavaClass path="TLS-Test-Framework/TestFramework/src/main/java/de/rub/nds/tlstest/framework/model/derivationParameter/CipherSuiteDerivation.java" />. Those enums in TLS-Attacker already include methods that return a `boolean` value to check if the enum value fullfills certain parameters. 

The methods specified in the `methods` array are called by using reflection on the selected enum value. If the return value is `true`, the combination of parameter values is considered as valid test input. Otherwise the test input is skipped.


### `ExplicitValues`
```java
public @interface ExplicitValues {
    Class<?> clazz() default Object.class;
    DerivationType[] affectedTypes();
    String[] methods();
}
```
Sometimes explicit values should be considered as parameter value, independent from the features that the <Definition id="SUT"/> supports. Those values are assigned to a parameter using this annotation.

The methods specified in the `methods` array are called by using reflection on `clazz` (test template class by default). The return value of the method should be `List<DerivationParameter>`.


### `ExplicitModelingConstraints`
```java
public @interface ExplicitModelingConstraints {
    Class<?> clazz() default Object.class;
    DerivationType[] affectedTypes();
    String[] methods();
}
```
This annotation replaces default constraints for a parameter with explicitly defined constraints. Each method of the `methods` array should return a list of <JavaClass path="TLS-Test-Framework/TestFramework/src/main/java/de/rub/nds/tlstest/framework/model/constraint/ConditionalConstraint.java" /> that should be applied to the given parameter at the correspondending index off the `affectedTypes` array.
