# Palladio-Addons-Confidentiality-Context-Analysis

![GitHub license](https://img.shields.io/github/license/FluidTrust/Palladio-Addons-ContextConfidentiality-Analysis)
![GitHub top language](https://img.shields.io/github/languages/top/FluidTrust/Palladio-Addons-ContextConfidentiality-Analysis)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/FluidTrust/Palladio-Addons-ContextConfidentiality-Analysis)
![GitHub Main Branch](https://img.shields.io/github/checks-status/FluidTrust/Palladio-Addons-ContextConfidentiality-Analysis/main)
## Tabele of Contents
* [Background](#Background)
* [Installation](#Installation)
* [License](#License)

## Background
This repository contains multiple Eclipse plugins to analyse confidentiality properties of a given software architecture. It uses the Palladio Component Model (PCM). Currently 2 types of analyses are supported:
1. Scenario analysis
    * different usage scenarios from PCM are analysed regarding the confidentiality
    * confidentiality is based on access control and whether certain services can be called with the given set of credentials
    * misusage scenarios are supported (similar to misusage diagrams)
2. Attacker propagation
    * propagation based on CVE and CWE vulnerabilites
    * supports different authorization levels and gaining of new credentials
## Installation
### Dependencies
* Java 11
* Eclipse Modelling Edition (min. 2020-12) with
    * PCM 5.0+ (see [PCM-Wiki](https://sdqweb.ipd.kit.edu/wiki/PCM_Installation))
    * Context and Attackermetamodel ([Updatesite](https://updatesite.palladio-simulator.com/fluidtrust/palladio-addons-contextconfidentiality-metamodel/nightly/), [Repo](https://github.com/FluidTrust/Palladio-Addons-ContextConfidentiality-Metamodel))
    * com.google.gson
    * com.google.guava
    * org.apache.commons.codec
    * org.apache.commons.lang3
    * org.slf4j.api
    * com.sun.xml.bind version="2.3.3"
    * jakarta.xml.bind version="2.3.3"
    * jakarta.activation version="1.2.2" 
    * org.apache.logging.log4j version="2.8.2"
    * (the ones without a link are available from [Eclipse Orbit](https://download.eclipse.org/tools/orbit/downloads/drops/R20210602031627/))

### Install with Updatesite (for users)
* Add the [Updatesite](https://updatesite.palladio-simulator.com/fluidtrust/palladio-addons-contextconfidentiality-analysis/nightly/) to eclipse
* install all offered features
    * source features are optional
### Install with local build (for developers)
* clone the repository (`git clone https://github.com/FluidTrust/Palladio-Addons-ContextConfidentiality-Metamodel.git`)
* run `mvn clean verify` within the cloned repository
* import all projects in the bundles folder into eclipse

## License
* The XACML pdp (`bundles/external-dependencies/lib`) is licensed under the Copyright (c) 2014 AT&T Intellectual Property see [Homepage](https://github.com/att/xacml-3.0).
* The rest is licensed under the [EPL-2.0](https://github.com/FluidTrust/Palladio-Addons-ContextConfidentiality-Analysis/blob/main/LICENSE)
