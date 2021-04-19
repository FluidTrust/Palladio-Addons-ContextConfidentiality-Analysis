package edu.kit.ipd.sdq.kamp4attack.tests;

import java.io.IOException;
import java.util.ArrayList;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EcorePackage;
import org.eclipse.emf.ecore.resource.Resource;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.BeforeEach;
import org.palladiosimulator.pcm.PcmPackage;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.allocation.AllocationPackage;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerPackage;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationPackage;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.ContextPackage;
import org.palladiosimulator.pcm.confidentiality.context.specification.SpecificationPackage;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyPackage;
import org.palladiosimulator.pcm.core.CorePackage;
import org.palladiosimulator.pcm.parameter.ParameterPackage;
import org.palladiosimulator.pcm.qosannotations.qos_reliability.QosReliabilityPackage;
import org.palladiosimulator.pcm.reliability.ReliabilityPackage;
import org.palladiosimulator.pcm.repository.RepositoryPackage;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.resourceenvironment.ResourceenvironmentPackage;
import org.palladiosimulator.pcm.resourcetype.ResourcetypePackage;
import org.palladiosimulator.pcm.seff.SeffPackage;
import org.palladiosimulator.pcm.seff.seff_reliability.SeffReliabilityPackage;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.system.SystemPackage;
import org.palladiosimulator.pcm.usagemodel.UsagemodelPackage;

import de.uka.ipd.sdq.identifier.IdentifierPackage;
import de.uka.ipd.sdq.probfunction.ProbfunctionPackage;
import de.uka.ipd.sdq.stoex.StoexPackage;
import de.uka.ipd.sdq.units.UnitsPackage;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.ModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.core.AttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

public abstract class AbstractModelTest {

    protected String PATH_ATTACKER;
    protected String PATH_ASSEMBLY;
    protected String PATH_ALLOCATION;
    protected String PATH_CONTEXT;
    protected String PATH_MODIFICATION;
    protected String PATH_REPOSITORY;
    protected String PATH_USAGE;
    protected String PATH_RESOURCES;

    protected System assembly;
    protected ResourceEnvironment environment;
    protected Allocation allocation;
    protected ConfidentialAccessSpecification context;
    protected AttackerSpecification attacker;
    protected AbstractKAMP4attackModificationRepository<?> modification;

    private Resource loadResource(final ResourceSet resourceSet, final String path) {
        return resourceSet.getResource(URI.createURI(path), true);
    }

    protected void execute() {
        final var wrapper = this.getBlackboardWrapper();
        (new AttackPropagationAnalysis()).runChangePropagationAnalysis(wrapper);
    }

    final protected BlackboardWrapper getBlackboardWrapper() {
        return new BlackboardWrapper(this.modification, this.assembly, this.environment, this.allocation,
                this.context.getPcmspecificationcontainer(), this.attacker.getSystemintegration());
    }

    @BeforeEach
    protected void loadModels() throws IOException {

        final EPackage[] ePackages = new EPackage[] { EcorePackage.eINSTANCE, IdentifierPackage.eINSTANCE,
                UnitsPackage.eINSTANCE, ProbfunctionPackage.eINSTANCE, PcmPackage.eINSTANCE, SeffPackage.eINSTANCE,
                RepositoryPackage.eINSTANCE, ParameterPackage.eINSTANCE, UsagemodelPackage.eINSTANCE,
                SystemPackage.eINSTANCE, ResourcetypePackage.eINSTANCE, ResourceenvironmentPackage.eINSTANCE,
                AllocationPackage.eINSTANCE, StoexPackage.eINSTANCE, CorePackage.eINSTANCE,
                /* CompletionsPackage.eINSTANCE, */ ReliabilityPackage.eINSTANCE, QosReliabilityPackage.eINSTANCE,
                SeffReliabilityPackage.eINSTANCE, KAMP4attackModificationmarksPackage.eINSTANCE,
                ModificationmarksPackage.eINSTANCE, ContextPackage.eINSTANCE, SpecificationPackage.eINSTANCE,
                AssemblyPackage.eINSTANCE, AttackerPackage.eINSTANCE, AttackSpecificationPackage.eINSTANCE };

        final var resourceSet = new ResourceSetImpl();

        for (final EPackage ePackage : ePackages) {
            resourceSet.getPackageRegistry().put(ePackage.getNsURI(), ePackage);
        }

        final var resourceAssembly = this.loadResource(resourceSet, this.PATH_ASSEMBLY);
        final var resourceAllocation = this.loadResource(resourceSet, this.PATH_ALLOCATION);
        final var resourceResource = this.loadResource(resourceSet, this.PATH_RESOURCES);
        final var resourceRepository = this.loadResource(resourceSet, this.PATH_REPOSITORY);
        final var resourceUsage = this.loadResource(resourceSet, this.PATH_USAGE);
        final var resourceContext = this.loadResource(resourceSet, this.PATH_CONTEXT);
        final var resourceAttacker = this.loadResource(resourceSet, this.PATH_ATTACKER);
        final var resourceModification = this.loadResource(resourceSet, this.PATH_MODIFICATION);

        final var list = new ArrayList<Resource>(resourceSet.getResources());
        for (final var res : list) {
            EcoreUtil.resolveAll(res);
        }

        this.assembly = (System) resourceAssembly.getContents().get(0);
        this.environment = (ResourceEnvironment) resourceResource.getContents().get(0);
        this.allocation = (Allocation) resourceAllocation.getContents().get(0);
        this.context = (ConfidentialAccessSpecification) resourceContext.getContents().get(0);
        this.attacker = (AttackerSpecification) resourceAttacker.getContents().get(0);
        resourceRepository.getContents().get(0);
        resourceUsage.getContents().get(0);
        this.modification = (AbstractKAMP4attackModificationRepository<?>) resourceModification.getContents().get(0);

        this.execute();

    }

}