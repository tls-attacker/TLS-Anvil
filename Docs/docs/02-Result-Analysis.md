# TLS-Anvil Result Analysis

*Analyzing Servers and Clients using Anvil Web*

## Introduction

This documentation describes how to analyze TLS-Anvil scan reports using Anvil Web.

**Importing Reports into Anvil Web**  
If the scan was created and executed from the Anvil Web interface using a connected worker, it will be available immediately in the report overview. If the scan was created using the command line tool, it must first be imported.

* Either a ZIP archive has already been created (by starting TLS-Anvil using the \-zip flag), if not, the output folder must be packed into a ZIP archive. The archive should look like this:  
  *\> report.zip*  
  ![](/img/result-analysis/report-file-structure.png)
* Upload the ZIP file under Tests → Upload Test  
  ![](/img/result-analysis/report-list.png)

After importing the test report, it can be opened and analyzed. Click on “Details” to go to the Report Overview.

**Report Overview**  
**![](/img/result-analysis/report-overview.png)**  
The report overview shows a rough overview of the test results.

* **Test started**: At what time the test was carried out.
* **Test Cases**: How many handshakes were performed \- this depends on the selected test strength and any active filters.
* **Elapsed Time**: How long the test took.
* **Scores**: Gives a rough overview of how many tests from which categories were successful (see below for more on the categories).
* **Test bar**: *red* \- tests with errors, *green* \- successful tests, *gray* \- tests not performed (e.g. because the feature to be tested is not supported or the test was disabled manually)
* **Guidelines**: There are various guidelines that stipulate which configuration TLS servers should have. Among others, the BSI prescribes how to secure a TLS server in its technical guideline TR-02102-2. The American NIST has a similar guideline. Tests are carried out here against these guidelines. This has nothing to do with actual errors in the implementation, as in the test runs below, but with the configuration of the server. The guideline check is performed by TLS-Scanner and is only additionally integrated here.

## Report Analysis

Below are the actual TLS-Anvil test results, broken down by test run. These are grouped into RFCs and can be restricted using various filters. Most test runs are based on an RFC citation. RFCs specify how TLS software must behave in order to comply with the standard. TLS is defined by many such RFCs. The RFC for TLS version 1.3, for example, is RFC 8446 and can be found here [https://www.rfc-editor.org/rfc/rfc8446](https://www.rfc-editor.org/rfc/rfc8446)

Each test has a randomly generated name according to the scheme \[RFC number\]-\[Random letters\].

**Filters**  
**![](/img/result-analysis/filters.png)**  
Each test has different properties, such as name, tags, categories and test result. All these properties can be filtered:

* **Name:** The name contains the RFC number and is otherwise random. It can be filtered using the free text search.
* **Tags:** Tags appear in gray after the name and provide additional information about the test, e.g. whether it is a TLS 1.2 (*tls12*) or TLS 1.3 test (*tls13*). Whether it is a server (*server*) or client test (*client*) or both (*both*). Tags can be filtered using the free text search.
* **Categories:** Tests are grouped into different categories. A test can belong to several categories at the same time. The categories indicate approximately what the test does and what relevance this test has.
    * **MessageStructure** → A test that checks whether the structure of messages is correct.
    * **Handshake** → A test that checks the structure of the handshake.
    * **Alert** → A test that checks for correctly sent alert messages.
    * **Security** → A test that checks security-relevant specifications. Failure to pass may indicate vulnerability to an attack.
    * **Interoperability** → A test in which failure to pass could mean that the tested software may not be compatible with other TLS libraries.
    * **Crypto** → A test that tests cryptographic functions. Failure to pass could lead to a loss of cryptographic security guarantees.
    * **RecordLayer** → Tests the RecordLayer of TLS.
    * **DeprecatedFeature** → Tests which use features that should no longer be supported.
    * **Certificate** → Tests that affect the certificate sent.
    * **CVE** → Tests that check for known, old vulnerabilities.
* **Test result:** The test result indicates how the respective test was completed.
    * Successful
        * *Strictly Succeeded* → Test passed.
        * *Conceptually Succeeded* → Test passed, but the connection was closed without notice.
    * Failed
        * *Fully Failed* → The test failed under every parameter combination. The tested software does not adhere to the RFC specification. The effects depend on the test.
        * *Partially Failed* → The test failed for certain parameter combinations (e.g. the test only fails when a certain cipher suite is selected). This indicates that there is probably an implementation error.
    * Error during execution (mainly relevant for developers of TLS-Anvil or if the TLS library still has compatibility problems)
        * *Parser Error*
        * *Not Specified*
        * *Incomplete*
        * *Test Suite Error*
    * *Disabled* → the test was not executed because the function to be tested is not supported or it was manually disabled.

**Debugging a Library**

* **Step 1:** Filter by Failed. To do this, you can click on the red part of the test bar or manually select the test results “Fully Failed” and “Partially Failed”.
* **Step 2:** Click on all red tests one by one and evaluate what the problem is (see below).  
  ![](/img/result-analysis/testrun-list.png)
* **Step 3:** When a test has been fully evaluated, the tick to the left of the test can be selected. This hides the test and moves it to the “Hidden” drop-down menu. Hidden tests can be shown again by pressing the “Reset Hidden” button (all) or by removing the tick.

## Testrun Evaluation

**Testrun Overview**  
![](/img/result-analysis/testrun-overview.png)  
If you click on an individual test run, you will see an overview at the top that shows the test name, the respective RFC and the quote that is being evaluated, as well as information on the test result.

* **RFC**: This shows which RFC is responsible for the test. The specification is displayed in the form of an RFC quote, as well as the chapter of the RFC in which it can be found.
* **Result**: Shows the test result. On the right-hand side you can also see how many handshakes were sent (here 21\) and how many of them passed the test (here 0). *Fully Failed* always means that 0 were successful. *Partially Failed* means that more than 0 but not all were successful. If all handshakes were successful, the result is *Strictly Succeeded* or *Conceptually Succeeded*.
* **Failure Inducing Combinations**: These are only relevant for Partially Failed tests and indicate which parameter is probably responsible for the error. This may help with troubleshooting.
* **Failed Reason**: The reason why the handshakes failed. Unfortunately, this is usually not directly understandable at present. “The workflow could not be executed as planned” means, for example, that a specific message was expected but another one was received. It is easier to understand the reason for the error if you take a closer look at the individual handshakes.

**List of Handshakes (Test Cases)**  
The individual handshakes are listed below. These are called test cases. Test runs are usually carried out several times with different parameter combinations. Such an execution is a handshake and can be displayed in the list at the bottom. The list is sorted according to the test result and the respective parameters used. There are rarely test runs that do not require a handshake; in these cases, the list is not displayed.

![](/img/result-analysis/testcase-list.png)

If the test is *Fully Failed*, any handshake can be used here for evaluation.

For *partially failed* tests, it is interesting to see under which conditions the test failed. It can be helpful to sort the table according to certain parameters. A small arrow next to the respective table headings can be used for this purpose. If you click on the heading instead, the respective column is removed and appears at the top of the list under “Hidden Parameters”. This can be useful if you are sure that the respective parameter is not relevant for the test.

In the simplest case, the error is dependent on just one parameter. You can then sort by this and you should see that the result column is also sorted. If the result is dependent on a combination of different parameters, it can be difficult to recognize which of the parameters is responsible for a failed handshake. Here again, the “Failure Inducing Combinations” from above can be helpful.

**Detail View**  
If you click on a handshake / test case, you can see all the details of the test procedure. The most interesting things here are the parameters used in each case, the additional information, which sometimes also includes the reason why the test failed, and the network traffic capture.  
![](/img/result-analysis/testcase-details.png)  
The following may be relevant here:

* **Result**: The result of the individual handshake.
* **AdditionalResultInformation**: Useful information about the test. May contain more information about why it failed.
* **Derivations**: The parameter combinations that were used.
* **Network Traffic Capture**: Which messages were sent. TLS messages are marked in blue. The complete PCAP recording can be downloaded below and analyzed using tools such as Wireshark.