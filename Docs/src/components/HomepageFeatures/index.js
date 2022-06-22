import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Easy to Use',
   // Svg: require('@site/static/img/undraw_docusaurus_mountain.svg').default,
    description: (
      <>
        TLS-Anvil is available as Docker Container, so there as no hassle for
        you to compile the project. The CLI provides all the options to test your
        TLS server or client. 
      </>
    ),
  },
  {
    title: 'Fully automated',
    //Svg: require('@site/static/img/undraw_docusaurus_tree.svg').default,
    description: (
      <>
        If everything works as expected, testing a TLS server or client is as
        easy as starting TLS-Anvil and let it know how to connect to your target.
        <br></br>However, there are for sure annoying implementations violating RFCs that
        TLS-Anvil fails to test out of the box.
      </>
    ),
  },
  {
    title: 'Extendible',
    //Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        TLS-Anvil currently has tests implemented for clients and servers supporting TLS 1.2
        and TLS 1.3. From the start of the project the goal was to build a framework
        that allows others to easily build additional tests.
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        {/* <Svg className={styles.featureSvg} role="img" /> */}
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
