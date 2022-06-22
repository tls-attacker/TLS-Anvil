export const definitions = {
  "ipm": {
    long: "Input Parameter Model",
    definition: "Contains all relevant test parameters and their values. The IPM is used to generate the test inputs (one value is assigned to each parameter) by using t-way combinatorial testing. Seperate IPMs are defined for each test template, depending on the requirement that the test template checks. Dynamically inserted constraints are applied to the IPM to ensure that for each parameter only values are used that are supported by the SUT."
  },
  "sut": {
    long: "System Under Test",
    definition: "The TLS client or server that you want to test using TLS-Anvil."
  },
  "test input(s)?": {
    long: "Test Input",
    definition: "A test input is basically a dictionary that contains a single value for each parameter of an IPM. Test inputs are automatically generated from the IPM using t-way combinatorial testing. A test template is executed multiple times using a different test input for each execution."
  },
  "test template(s)?": {
    long: "Test Template",
    definition: "A test template defines the desired outcome for all test cases derived from it. Thus, it represents a test oracle that is applicable to all derived test cases. Each test template tests a different requirement and is implemented as a normal JUnit test. It basically consists of two building blocks. First it defines which TLS messages are sent and expected to be received by the test suite. Second, it defines when a test case succeeds or fails."
  },
  "test case(s)?": {
    long: "Test Case",
    definition: "A test case is the (automatically) instantiated version of test template with one specific test input."
  }
}