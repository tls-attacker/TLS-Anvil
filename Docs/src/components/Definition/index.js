import React, {useState} from 'react';
import Tippy from '@tippyjs/react';
import 'tippy.js/dist/tippy.css'; // optional
import styles from './styles.module.css';
import { definitions } from '../../../definitions';



const defs = Object.keys(definitions)



export default function Definition({id}) {
  const key = defs.map(i => [new RegExp(i, "i").test(id), i]).filter(i => i[0])[0][1]
  const details = definitions[key]

  return (
    <>
      <Tippy content={<Details details={details} />} placement="bottom" arrow={true} hideOnClick={true}>
        <span className={styles.tag}>{id}&nbsp;&#9432;</span>
      </Tippy>
    </>
  )
}


function Details({details}) {
  return (
    <>
      <div>{details.long}</div>
      <hr style={{"marginTop": "4px", "marginBottom": "4px"}}/>
      <div>{details.definition}</div>
    </>
  )
}

