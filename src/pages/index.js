import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import Fire from '@site/src/pages/Fire';
//import Translate from '@docusaurus/Translate';

import Heading from '@theme/Heading';
import styles from './index.module.css';

import { Helmet } from 'react-helmet';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title" style={{ color: 'white', }}>
          {siteConfig.title}
        </Heading>
        <Helmet>
        <link
          href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@400;700&display=swap"
          rel="stylesheet"
        />
      </Helmet>
        <p className="hero__subtitle" style={{ color: 'white' }}>{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          {<Link
            className="button button--secondary button--lg"
            to="/blog">
            Loglara git 
          </Link>}
        </div>
      </div>
    </header>
  );
}



export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title}`}
      description="b_log">
      <HomepageHeader />
      <Fire />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
