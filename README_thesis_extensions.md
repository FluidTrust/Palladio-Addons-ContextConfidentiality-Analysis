# Attack Surface Analysis

See also the main README.md. Here are only additional information on how to install the attack surface analysis extension prototype implementation for the approach presented in the thesis.

## Installation and Dependenices
1. Installation Eclipse Modeling Tools 2021-12 ( https://www.eclipse.org/downloads/packages/ ) and Palladio 5.1 via the Eclipse Marketplace or direct Installation of the Palladio-Bench
2. Installation allPrerequisites.p2f in Eclipse with Import > Install Software Items from File
3. Get Analysis and Metamodel directories from Zenodo
4. Import into Eclipse the two directories, firstly der metamodel, then the analysis
5. execute /org.palladiosimulator.pcm.confidentiality.context.mwe2 Workflows clean, generate
6. execute /org.palladiosimulator.pcm.confidentiality.attacker.mwe2 Workflows clean, generate
7. execute /edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.mwe2 Workflows clean, generate
8. generate all /org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel via genmodel
9. delete all projects with the name "variation" from the workspace
10. there are only 3 errors with the message "Zero representation file ...", these can be ignored

Where is what?:
- the main part of the implementation: /edu.kit.sdq.attacksurface
- the tests: /edu.kit.sdq.attacksurface.tests (must be started as JUnit-Plugin Test)
- metamodels:
	- context specification: org.palladiosimulator.pcm.confidentiality.context
	- attacker specification: org.palladiosimulator.pcm.confidentiality.attacker
	- KAMP4attackModmarks: edu.kit.ipd.sdq.kamp4attack.model.modificationmarks (is in the Analyis directory)
