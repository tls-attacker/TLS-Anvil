"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[41],{1293:function(e,t,n){n.d(t,{Z:function(){return r}});var a=n(7294),i=n(860),s=(n(8846),"tag_sbMh"),l={ipm:{long:"Input Parameter Model",definition:"Contains all relevant test parameters and their values. The IPM is used to generate the test inputs (one value is assigned to each parameter) by using t-way combinatorial testing. Seperate IPMs are defined for each test template, depending on the requirement that the test template checks. Dynamically inserted constraints are applied to the IPM to ensure that for each parameter only values are used that are supported by the SUT."},sut:{long:"System Under Test",definition:"The TLS client or server that you want to test using TLS-Anvil."},"test input(s)?":{long:"Test Input",definition:"A test input is basically a dictionary that contains a single value for each parameter of an IPM. Test inputs are automatically generated from the IPM using t-way combinatorial testing. A test template is executed multiple times using a different test input for each execution."},"test template(s)?":{long:"Test Template",definition:"A test template defines the desired outcome for all test cases derived from it. Thus, it represents a test oracle that is applicable to all derived test cases. Each test template tests a different requirement and is implemented as a normal JUnit test. It basically consists of two building blocks. First it defines which TLS messages are sent and expected to be received by the test suite. Second, it defines when a test case succeeds or fails."},"test case(s)?":{long:"Test Case",definition:"A test case is the (automatically) instantiated version of test template with one specific test input."}},o=Object.keys(l);function r(e){var t=e.id,n=o.map((function(e){return[new RegExp(e,"i").test(t),e]})).filter((function(e){return e[0]}))[0][1],r=l[n];return a.createElement(a.Fragment,null,a.createElement(i.ZP,{content:a.createElement(p,{details:r}),placement:"bottom",arrow:!0,hideOnClick:!0},a.createElement("span",{className:s},t,"\xa0\u24d8")))}function p(e){var t=e.details;return a.createElement(a.Fragment,null,a.createElement("div",null,t.long),a.createElement("hr",{style:{marginTop:"4px",marginBottom:"4px"}}),a.createElement("div",null,t.definition))}},727:function(e,t,n){n.r(t),n.d(t,{assets:function(){return u},contentTitle:function(){return d},default:function(){return f},frontMatter:function(){return p},metadata:function(){return c},toc:function(){return m}});var a=n(7462),i=n(3366),s=(n(7294),n(3905)),l=n(5710),o=n(1293),r=["components"],p={},d="Result Analysis",c={unversionedId:"Quick-Start/Result-Analysis",id:"Quick-Start/Result-Analysis",title:"Result Analysis",description:"TLS-Anvil stores the test results in multiple json files. In addition the network traffic is captured with tcpdump during the execution. Since analyzing those files by hand is tedious, we created a small web application to get the job done.",source:"@site/docs/01-Quick-Start/03-Result-Analysis.md",sourceDirName:"01-Quick-Start",slug:"/Quick-Start/Result-Analysis",permalink:"/docs/Quick-Start/Result-Analysis",draft:!1,editUrl:"https://github.com/tls-attacker/TLS-Anvil/tree/main/Docs/docs/01-Quick-Start/03-Result-Analysis.md",tags:[],version:"current",sidebarPosition:3,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Client Testing",permalink:"/docs/Quick-Start/Client-Testing"},next:{title:"Architecture",permalink:"/docs/Architecture"}},u={},m=[{value:"Start the application",id:"start-the-application",level:3},{value:"Importing the results",id:"importing-the-results",level:3},{value:"Using the application",id:"using-the-application",level:3},{value:"Possible Test Results",id:"possible-test-results",level:3}],h={toc:m};function f(e){var t=e.components,n=(0,i.Z)(e,r);return(0,s.kt)("wrapper",(0,a.Z)({},h,n,{components:t,mdxType:"MDXLayout"}),(0,s.kt)("h1",{id:"result-analysis"},"Result Analysis"),(0,s.kt)("p",null,"TLS-Anvil stores the test results in multiple ",(0,s.kt)("inlineCode",{parentName:"p"},"json")," files. In addition the network traffic is captured with ",(0,s.kt)("inlineCode",{parentName:"p"},"tcpdump")," during the execution. Since analyzing those files by hand is tedious, we created a small web application to get the job done."),(0,s.kt)("p",null,"The result analyzer application is also shipped as docker container. Since a database is required, ",(0,s.kt)("inlineCode",{parentName:"p"},"docker-compose")," is the easiest way to start the application. The ",(0,s.kt)("inlineCode",{parentName:"p"},"docker-compose.yml")," file is part our ",(0,s.kt)("a",{parentName:"p",href:"https://github.com/tls-attacker/TLS-Anvil"},"GitHub Repo"),". Alternatively you can copy & paste it from here."),(0,s.kt)("details",null,(0,s.kt)("summary",null,"Result Analyzer Docker Compose File"),(0,s.kt)(l.Z,{language:"yml",title:"Result-Analyzer/docker-compose.yml",mdxType:"CodeBlock"},"version: '3.7'\n\nvolumes:\n  mongodb_DB:\n  mongodb_conf:\n\nnetworks: \n  app:\n\nservices:\n  mongo:\n    image: mongo\n    restart: always\n    volumes:\n      - mongodb_DB:/data/db\n      - mongodb_conf:/data/configdb\n    ports:\n      - 27017:27017\n    networks: \n      - app\n\n  mongo-express:\n    image: mongo-express\n    restart: always\n    ports:\n      - 8081:8081\n    networks:\n      - app\n\n  app:\n    image: ghcr.io/tls-attacker/tlsanvil-reportanalyzer\n    restart: always\n    environment: \n      PRODUCTION: '1'\n    build: \n      context: .\n      args:\n        REST_API_BASE_URL: http://localhost:5000/api/v1\n    ports:\n      - 5000:5000\n    networks:\n      - app\n\n\n")),(0,s.kt)("h3",{id:"start-the-application"},"Start the application"),(0,s.kt)("p",null,"First we start the web application."),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"docker-compose pull\ndocker-compose up -d\n")),(0,s.kt)("p",null,"The application should be available at ",(0,s.kt)("a",{parentName:"p",href:"http://localhost:5000"},"http://localhost:5000"),"."),(0,s.kt)("h3",{id:"importing-the-results"},"Importing the results"),(0,s.kt)("p",null,"Next the results need to be imported, i.e. importing the JSON files of TLS-Anvil into a MongoDB that is accessed by the backend of the web application. The uploader tool is also available as Docker image."),(0,s.kt)("p",null,(0,s.kt)("inlineCode",{parentName:"p"},"cd")," into any folder where child folders contain test results and run the uploader tool. It searches recursively for TLS-Anvil result reports and imports all of them into the database."),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"cd results\ndocker run \\\n    --rm \\\n    -it \\\n    --network host \\\n    -v $(pwd):/upload \\\n    ghcr.io/tls-attacker/tlsanvil-result-uploader:latest\n")),(0,s.kt)("h3",{id:"using-the-application"},"Using the application"),(0,s.kt)("ol",null,(0,s.kt)("li",{parentName:"ol"},"Open your web browser at ",(0,s.kt)("a",{parentName:"li",href:"http://localhost:5000"},"http://localhost:5000"),"."),(0,s.kt)("li",{parentName:"ol"},"Click ",(0,s.kt)("inlineCode",{parentName:"li"},"Analyzer")," in the navbar and select the uploaded report from the dropdown menu on the top left.",(0,s.kt)("ul",{parentName:"li"},(0,s.kt)("li",{parentName:"ul"},"If the menu is empty, reload the page."))),(0,s.kt)("li",{parentName:"ol"},"The result for each ",(0,s.kt)(o.Z,{id:"test template",mdxType:"Definition"})," is presented in the table."),(0,s.kt)("li",{parentName:"ol"},"The table rows are clickable and show the results for each ",(0,s.kt)(o.Z,{id:"test input",mdxType:"Definition"}),", i.e. each performed handshake.",(0,s.kt)("ol",{parentName:"li"},(0,s.kt)("li",{parentName:"ol"},"Click on a test result icon of a test case to view the recorded PCAP dump for the handshake as well as additional information about the handshake. ",(0,s.kt)("inlineCode",{parentName:"li"},"DerivationContainer"),", for example, shows the ",(0,s.kt)(o.Z,{id:"test input",mdxType:"Definition"})," for the test case, generated by the combinatorial testing algorithm."),(0,s.kt)("li",{parentName:"ol"},"Click on the table column head (first row) to see more information about the ",(0,s.kt)(o.Z,{id:"test template",mdxType:"Definition"}),", including the failure inducing combinations.")))),(0,s.kt)("h3",{id:"possible-test-results"},"Possible Test Results"),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"Strictly Succeeded (\u2705)"),(0,s.kt)("br",{parentName:"p"}),"\n","A strictly succeeded test means that the ",(0,s.kt)(o.Z,{id:"SUT",mdxType:"Definition"})," behaved exactly as expected. If multiple ",(0,s.kt)(o.Z,{id:"test cases",mdxType:"Definition"})," are performed during the execution of a ",(0,s.kt)(o.Z,{id:"test template",mdxType:"Definition"}),", the ",(0,s.kt)(o.Z,{id:"SUT",mdxType:"Definition"})," must have behaved correctly across all of them."),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"Conceptually Succeeded (\u26a0\ufe0f\u2705)"),(0,s.kt)("br",{parentName:"p"}),"\n","A conceptually succeeded test means that an implementation did not precisely fulfill the RFC requirements or did not do so in all ",(0,s.kt)(o.Z,{id:"test cases",mdxType:"Definition"})," but effectively behaved correctly. This usually applies to tests where a fatal alert was expected, but the library either only closed the connection but did not send an alert, or the alert description did not match the RFC's specification."),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"Partially Failed (\u26a0\ufe0f\u274c)"),(0,s.kt)("br",{parentName:"p"}),"\n","When multiple handshakes are performed for a ",(0,s.kt)(o.Z,{id:"test template",mdxType:"Definition"}),", the partially failed result indicates that not all ",(0,s.kt)(o.Z,{id:"test inputs",mdxType:"Definition"})," failed for a specific ",(0,s.kt)(o.Z,{id:"test template",mdxType:"Definition"}),"."),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"Fully Failed (\u274c)"),(0,s.kt)("br",{parentName:"p"}),"\n","A fully failed result means that the ",(0,s.kt)(o.Z,{id:"SUT",mdxType:"Definition"})," did not behave correctly for any ",(0,s.kt)(o.Z,{id:"test input",mdxType:"Definition"}),"."))}f.isMDXComponent=!0}}]);