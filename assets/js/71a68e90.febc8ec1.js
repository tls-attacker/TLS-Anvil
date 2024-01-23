"use strict";(self.webpackChunktls_anvil_docs=self.webpackChunktls_anvil_docs||[]).push([[41],{2726:(e,t,s)=>{s.r(t),s.d(t,{assets:()=>d,contentTitle:()=>r,default:()=>p,frontMatter:()=>l,metadata:()=>o,toc:()=>c});var i=s(5893),a=s(1151),n=(s(9286),s(1293));const l={},r="Result Analysis",o={id:"Quick-Start/Result-Analysis",title:"Result Analysis",description:"TLS-Anvil stores the test results in multiple json files. In addition the network traffic is captured during the execution. Since analyzing those files by hand is tedious, we created a small web application to get the job done.",source:"@site/docs/01-Quick-Start/03-Result-Analysis.md",sourceDirName:"01-Quick-Start",slug:"/Quick-Start/Result-Analysis",permalink:"/docs/Quick-Start/Result-Analysis",draft:!1,unlisted:!1,editUrl:"https://github.com/tls-attacker/TLS-Anvil/tree/main/Docs/docs/01-Quick-Start/03-Result-Analysis.md",tags:[],version:"current",sidebarPosition:3,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Client Testing",permalink:"/docs/Quick-Start/Client-Testing"},next:{title:"Architecture",permalink:"/docs/Architecture"}},d={},c=[{value:"Start the application",id:"start-the-application",level:3},{value:"Importing the results",id:"importing-the-results",level:3},{value:"Using the application",id:"using-the-application",level:3},{value:"Possible Test Results",id:"possible-test-results",level:3},{value:"Result Annotations",id:"result-annotations",level:3}];function h(e){const t={a:"a",br:"br",code:"code",h1:"h1",h3:"h3",li:"li",ol:"ol",p:"p",pre:"pre",strong:"strong",...(0,a.a)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(t.h1,{id:"result-analysis",children:"Result Analysis"}),"\n",(0,i.jsxs)(t.p,{children:["TLS-Anvil stores the test results in multiple ",(0,i.jsx)(t.code,{children:"json"})," files. In addition the network traffic is captured during the execution. Since analyzing those files by hand is tedious, we created a small web application to get the job done."]}),"\n",(0,i.jsxs)(t.p,{children:["The result analyzer application is also shipped as docker container. Since a database is required, ",(0,i.jsx)(t.code,{children:"docker-compose"})," is the easiest way to start the application. The ",(0,i.jsx)(t.code,{children:"docker-compose.yml"})," file is part the ",(0,i.jsx)(t.a,{href:"https://github.com/tls-attacker/Anvil-Web",children:"Anvil-Web GitHub Repo"}),"."]}),"\n",(0,i.jsx)(t.p,{children:(0,i.jsx)(t.a,{href:"https://github.com/tls-attacker/Anvil-Web/blob/main/docker-compose.yml",children:"Download docker-compose.yml"})}),"\n",(0,i.jsx)(t.h3,{id:"start-the-application",children:"Start the application"}),"\n",(0,i.jsx)(t.p,{children:"First we start the web application."}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"docker-compose pull\ndocker-compose up -d\n"})}),"\n",(0,i.jsxs)(t.p,{children:["The application should be available at ",(0,i.jsx)(t.a,{href:"http://localhost:5001",children:"http://localhost:5001"}),"."]}),"\n",(0,i.jsx)(t.h3,{id:"importing-the-results",children:"Importing the results"}),"\n",(0,i.jsxs)(t.p,{children:["Next the results need to be imported, i.e. importing the JSON files of TLS-Anvil into a MongoDB that is accessed by the backend of the web application.\nThe easiest way to do that is to zip your results folder (the folder that contains the report.json file) and upload it in the web-interface.\nJust go to ",(0,i.jsx)(t.code,{children:"Tests"})," -> ",(0,i.jsx)(t.code,{children:"Upload Test"})," and select the zip file."]}),"\n",(0,i.jsx)(t.h3,{id:"using-the-application",children:"Using the application"}),"\n",(0,i.jsxs)(t.ol,{children:["\n",(0,i.jsxs)(t.li,{children:["Open your web browser at ",(0,i.jsx)(t.a,{href:"http://localhost:5001",children:"http://localhost:5001"}),"."]}),"\n",(0,i.jsxs)(t.li,{children:["Click ",(0,i.jsx)(t.code,{children:"Tests"})," in the navbar (if not already selected) and look for the test you just uploaded. Here you can click on ",(0,i.jsx)(t.code,{children:"Details"}),"."]}),"\n",(0,i.jsxs)(t.li,{children:["You will see an overview over the testresults. The specific result for each ",(0,i.jsx)(n.Z,{id:"test template"})," is presented in the table at the bottom, sorted by RFC."]}),"\n",(0,i.jsxs)(t.li,{children:["The table rows are clickable, if you do, a detailed view will be presented to you showing what exactly got tested in that run and the results for each ",(0,i.jsx)(n.Z,{id:"test input"}),", i.e. each performed handshake.","\n",(0,i.jsxs)(t.ol,{children:["\n",(0,i.jsxs)(t.li,{children:["Click on a row of a test case to view the recorded PCAP dump for the handshake as well as additional information about the handshake. ",(0,i.jsx)(t.code,{children:"Parameter Combination"}),", for example, shows the ",(0,i.jsx)(n.Z,{id:"test input"})," for the test case, generated by the combinatorial testing algorithm."]}),"\n"]}),"\n"]}),"\n"]}),"\n",(0,i.jsx)(t.h3,{id:"possible-test-results",children:"Possible Test Results"}),"\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Strictly Succeeded (\u2705)"}),(0,i.jsx)(t.br,{}),"\n","A strictly succeeded test means that the ",(0,i.jsx)(n.Z,{id:"SUT"})," behaved exactly as expected. If multiple ",(0,i.jsx)(n.Z,{id:"test cases"})," are performed during the execution of a ",(0,i.jsx)(n.Z,{id:"test template"}),", the ",(0,i.jsx)(n.Z,{id:"SUT"})," must have behaved correctly across all of them."]}),"\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Conceptually Succeeded (\u26a0\ufe0f\u2705)"}),(0,i.jsx)(t.br,{}),"\n","A conceptually succeeded test means that an implementation did not precisely fulfill the RFC requirements or did not do so in all ",(0,i.jsx)(n.Z,{id:"test cases"})," but effectively behaved correctly. This usually applies to tests where a fatal alert was expected, but the library either only closed the connection but did not send an alert, or the alert description did not match the RFC's specification."]}),"\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Partially Failed (\u26a0\ufe0f\u274c)"}),(0,i.jsx)(t.br,{}),"\n","When multiple handshakes are performed for a ",(0,i.jsx)(n.Z,{id:"test template"}),", the partially failed result indicates that not all ",(0,i.jsx)(n.Z,{id:"test inputs"})," failed for a specific ",(0,i.jsx)(n.Z,{id:"test template"}),"."]}),"\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Fully Failed (\u274c)"}),(0,i.jsx)(t.br,{}),"\n","A fully failed result means that the ",(0,i.jsx)(n.Z,{id:"SUT"})," did not behave correctly for any ",(0,i.jsx)(n.Z,{id:"test input"}),"."]}),"\n",(0,i.jsx)(t.h3,{id:"result-annotations",children:"Result Annotations"}),"\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Additional Information (\u2757\ufe0f)"}),"\nIn some cases, test templates highlight details that affected the result of a test. Tests with these details are indicated by an exclamation mark. When viewing the individual sessions of a test, the collected details are shown when hovering on a single result."]}),"\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Contradictory Additional information (\u2049\ufe0f)"}),"\nIf a test template added additional details for the result but these details differ between individual test cases of the template, the test result is annotated with ' \u2049\ufe0f '. This may hint towards unexpected behavioral differences. In the result view, you can filter for results with specific additional information."]})]})}function p(e={}){const{wrapper:t}={...(0,a.a)(),...e.components};return t?(0,i.jsx)(t,{...e,children:(0,i.jsx)(h,{...e})}):h(e)}},1293:(e,t,s)=>{s.d(t,{Z:()=>o});s(7294);var i=s(7083);s(8846);const a={tag:"tag_sbMh"},n={ipm:{long:"Input Parameter Model",definition:"Contains all relevant test parameters and their values. The IPM is used to generate the test inputs (one value is assigned to each parameter) by using t-way combinatorial testing. Seperate IPMs are defined for each test template, depending on the requirement that the test template checks. Dynamically inserted constraints are applied to the IPM to ensure that for each parameter only values are used that are supported by the SUT."},sut:{long:"System Under Test",definition:"The TLS client or server that you want to test using TLS-Anvil."},"test input(s)?":{long:"Test Input",definition:"A test input is basically a dictionary that contains a single value for each parameter of an IPM. Test inputs are automatically generated from the IPM using t-way combinatorial testing. A test template is executed multiple times using a different test input for each execution."},"test template(s)?":{long:"Test Template",definition:"A test template defines the desired outcome for all test cases derived from it. Thus, it represents a test oracle that is applicable to all derived test cases. Each test template tests a different requirement and is implemented as a normal JUnit test. It basically consists of two building blocks. First it defines which TLS messages are sent and expected to be received by the test suite. Second, it defines when a test case succeeds or fails."},"test case(s)?":{long:"Test Case",definition:"A test case is the (automatically) instantiated version of test template with one specific test input."}};var l=s(5893);const r=Object.keys(n);function o(e){let{id:t}=e;const s=r.map((e=>[new RegExp(e,"i").test(t),e])).filter((e=>e[0]))[0][1],o=n[s];return(0,l.jsx)(l.Fragment,{children:(0,l.jsx)(i.ZP,{content:(0,l.jsx)(d,{details:o}),placement:"bottom",arrow:!0,hideOnClick:!0,children:(0,l.jsxs)("span",{className:a.tag,children:[t,"\xa0\u24d8"]})})})}function d(e){let{details:t}=e;return(0,l.jsxs)(l.Fragment,{children:[(0,l.jsx)("div",{children:t.long}),(0,l.jsx)("hr",{style:{marginTop:"4px",marginBottom:"4px"}}),(0,l.jsx)("div",{children:t.definition})]})}}}]);