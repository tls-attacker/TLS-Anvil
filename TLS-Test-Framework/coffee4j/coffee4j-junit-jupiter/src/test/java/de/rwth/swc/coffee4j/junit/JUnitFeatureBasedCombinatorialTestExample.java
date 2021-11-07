package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.generator.Generator;
import de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.aggregator.AggregateWith;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.aggregator.ArgumentsAggregationException;
import org.junit.jupiter.params.aggregator.ArgumentsAggregator;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;
import org.junit.jupiter.params.converter.ConvertWith;

import static de.rwth.swc.coffee4j.model.InputParameterModel.inputParameterModel;
import static de.rwth.swc.coffee4j.model.Parameter.parameter;

/**
 * Demonstrates the use of junit {@link ConvertWith} and {@link AggregateWith} in combination with
 * {@link CombinatorialTest}. In the output you should see the actual person object and integer converted
 * for the test.
 * Additionally, the {@link de.rwth.swc.tiger.junit.CombinatorialTestParameterResolver} is demonstrated
 * with the output of "{firstName} at index {index}" per test instead of the default "[{index}] {combination}"
 */
class JUnitFeatureBasedCombinatorialTestExample {
    
    @CombinatorialTest(name = "{firstName} at index {index}")
    @ModelFromMethod("model")
    void combinatorialTest(@ConvertWith(WrittenNumberConverter.class) int number, @AggregateWith(PersonAggregator.class) Person person) {
        System.out.println("Person: " + person);
        System.out.println("number: " + number);
    }
    
    private static InputParameterModel.Builder model() {
        return inputParameterModel("test testModel").strength(3).parameters(parameter("number").values("one", "two", "three"), parameter("firstName").values("Alice", "Bob"), parameter("lastName").values("Smith", "Brown"), parameter("age").values(0, 10, 20, 30, 40));
    }
    
    private static final class Person {
        
        private final String firstName;
        
        private final String lastName;
        
        private final int age;
        
        private Person(String firstName, String lastName, int age) {
            this.firstName = firstName;
            this.lastName = lastName;
            this.age = age;
        }
        
        @Override
        public String toString() {
            return "Person{firstName='" + firstName + "\', lastName='" + lastName + "\', age=" + age + '}';
        }
        
    }
    
    private static final class PersonAggregator implements ArgumentsAggregator {
        
        @Override
        public Object aggregateArguments(ArgumentsAccessor argumentsAccessor, ParameterContext parameterContext) throws ArgumentsAggregationException {
            return new Person(argumentsAccessor.getString(1), argumentsAccessor.getString(2), argumentsAccessor.getInteger(3));
        }
        
    }
    
    private static final class WrittenNumberConverter implements ArgumentConverter {
        
        @Override
        public Object convert(Object o, ParameterContext parameterContext) throws ArgumentConversionException {
            if (o.equals("one")) {
                return 1;
            } else if (o.equals("two")) {
                return 2;
            } else {
                return 3;
            }
        }
        
    }
    
}
