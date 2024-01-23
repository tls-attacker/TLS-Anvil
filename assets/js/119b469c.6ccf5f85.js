"use strict";(self.webpackChunktls_anvil_docs=self.webpackChunktls_anvil_docs||[]).push([[811],{8800:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>c,contentTitle:()=>l,default:()=>d,frontMatter:()=>r,metadata:()=>a,toc:()=>o});var i=n(5893),s=n(1151);const r={},l="Client Testing",a={id:"Quick-Start/Client-Testing",title:"Client Testing",description:"This site demonstrates how to test the OpenSSL client provided by the TLS-Docker-Library.",source:"@site/docs/01-Quick-Start/02-Client-Testing.md",sourceDirName:"01-Quick-Start",slug:"/Quick-Start/Client-Testing",permalink:"/docs/Quick-Start/Client-Testing",draft:!1,unlisted:!1,editUrl:"https://github.com/tls-attacker/TLS-Anvil/tree/main/Docs/docs/01-Quick-Start/02-Client-Testing.md",tags:[],version:"current",sidebarPosition:2,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Server Testing",permalink:"/docs/Quick-Start/Server-Testing"},next:{title:"Result Analysis",permalink:"/docs/Quick-Start/Result-Analysis"}},c={},o=[{value:"Preperations",id:"preperations",level:3},{value:"Starting the TLS-Anvil container",id:"starting-the-tls-anvil-container",level:3},{value:"Starting the OpenSSL client container",id:"starting-the-openssl-client-container",level:3}];function h(e){const t={code:"code",h1:"h1",h3:"h3",li:"li",p:"p",pre:"pre",ul:"ul",...(0,s.a)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(t.h1,{id:"client-testing",children:"Client Testing"}),"\n",(0,i.jsx)(t.p,{children:"This site demonstrates how to test the OpenSSL client provided by the TLS-Docker-Library.\nTesting the client in the most simple form roughly takes around 15 minutes. However, this duration can increase to several depending on the strength parameter that that basically defines how often a single test case triggered with different parameters."}),"\n",(0,i.jsx)(t.h3,{id:"preperations",children:"Preperations"}),"\n",(0,i.jsx)(t.p,{children:"Similar to the server test we first create a dedicated docker network that is used by the TLS-Anvil and OpenSSL client container to communicate with each other."}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"docker network create tls-anvil\n"})}),"\n",(0,i.jsx)(t.h3,{id:"starting-the-tls-anvil-container",children:"Starting the TLS-Anvil container"}),"\n",(0,i.jsx)(t.p,{children:"Since the client has to connect to TLS-Anvil the test suite container is started first."}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",metastring:"showLineNumbers",children:"docker run \\\n    --rm \\\n    -it \\\n    -v $(pwd):/output/ \\\n    --network tls-anvil \\\n    --name tls-anvil \\\n    ghcr.io/tls-attacker/tlsanvil:latest \\\n    -outputFolder ./ \\\n    -parallelTestCases 3 \\\n    -parallelTests 3 \\\n    -strength 1 \\\n    -identifier openssl-client \\\n    client \\\n    -port 8443 \\\n    -triggerScript curl --connect-timeout 2 openssl-client:8090/trigger\n"})}),"\n",(0,i.jsxs)(t.ul,{children:["\n",(0,i.jsx)(t.li,{children:"Lines 2-6: Docker related command flags"}),"\n",(0,i.jsx)(t.li,{children:"Line 7: Specifies the TLS-Anvil docker image"}),"\n",(0,i.jsx)(t.li,{children:"Lines 9-10: Since the client can started multiple times, TLS-Anvil can run multiple tests and handshakes in parallel"}),"\n",(0,i.jsxs)(t.li,{children:["Line 11: Defines the strength, i.e. the ",(0,i.jsx)(t.code,{children:"t"})," for t-way combinatorial testing"]}),"\n",(0,i.jsx)(t.li,{children:"Line 12: Defines an arbitrary name that is written to the report"}),"\n",(0,i.jsx)(t.li,{children:"Line 13: We want to test a client"}),"\n",(0,i.jsx)(t.li,{children:"Line 14: The port on which TLS-Anvil listens to accept requests from the client"}),"\n",(0,i.jsx)(t.li,{children:"Line 15: Specifies a script that is executed before each handshake, which the goal to trigger a connection from the client. See below how this works."}),"\n"]}),"\n",(0,i.jsx)(t.h3,{id:"starting-the-openssl-client-container",children:"Starting the OpenSSL client container"}),"\n",(0,i.jsx)(t.p,{children:"The OpenSSL client image is provided by the TLS-Docker-Library. The entrypoint of the client images is a small HTTP server that provides two REST-API endpoints on port 8090."}),"\n",(0,i.jsxs)(t.ul,{children:["\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.code,{children:"GET /trigger"})," starts the client"]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.code,{children:"GET /shutdown"})," shutdown the HTTP server to terminate the container"]}),"\n"]}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",metastring:"showLineNumbers",children:"docker run \\\n    -d \\\n    --rm \\\n    --name openssl-client \\\n    --network tls-anvil \\\n    ghcr.io/tls-attacker/openssl-client:1.1.1i \\\n    -connect tls-anvil:8443\n"})}),"\n",(0,i.jsxs)(t.ul,{children:["\n",(0,i.jsx)(t.li,{children:"Lines 2-5: Docker related command flags"}),"\n",(0,i.jsx)(t.li,{children:"Line 7: Specifies the OpenSSL client image from the TLS-Docker-Library"}),"\n",(0,i.jsxs)(t.li,{children:["Line 8: This is passed to the OpenSSL ",(0,i.jsx)(t.code,{children:"s_client"})," binary, which is started each time a HTTP-GET request is sent to ",(0,i.jsx)(t.code,{children:":8090/trigger"}),"."]}),"\n"]})]})}function d(e={}){const{wrapper:t}={...(0,s.a)(),...e.components};return t?(0,i.jsx)(t,{...e,children:(0,i.jsx)(h,{...e})}):h(e)}},1151:(e,t,n)=>{n.d(t,{Z:()=>a,a:()=>l});var i=n(7294);const s={},r=i.createContext(s);function l(e){const t=i.useContext(r);return i.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function a(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(s):e.components||s:l(e.components),i.createElement(r.Provider,{value:t},e.children)}}}]);