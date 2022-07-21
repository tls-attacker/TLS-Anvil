import React from 'react'


export default function JavaClass({path}) {
  const comps = path.replace(".java", "").split("/").reverse()

  return <>
    <a href={"https://github.com/tls-attacker/TLS-Anvil/tree/main/" + path}>{comps[0]}</a>
  </>
}
