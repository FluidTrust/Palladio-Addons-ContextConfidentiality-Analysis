package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EcorePackage;
import org.eclipse.emf.ecore.resource.Resource;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.eclipse.emf.ecore.xmi.impl.XMIResourceFactoryImpl;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
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
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

class TestModels {

    private final static String PATH_ATTACKER = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/My.attacker";
    private final static String PATH_ASSEMBLY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/newAssembly.system";
    private final static String PATH_ALLOCATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/newAllocation.allocation";
    private final static String PATH_CONTEXT = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/My.context";
    private final static String PATH_MODIFICATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/My.kamp4attackmodificationmarks";
    private final static String PATH_REPOSITORY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/newRepository.repository";
    private final static String PATH_USAGE = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/newUsageModel.usagemodel";
    private final static String PATH_RESOURCES = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/GetAssemblyContext/newResourceEnvironment.resourceenvironment";

    static System assembly;
    static ResourceEnvironment environment;
    static Allocation allocation;
    static ConfidentialAccessSpecification context;
    static AttackerSpecification attacker;
    static AbstractKAMP4attackModificationRepository<?> modification;

    @BeforeAll
    static void loadModels() throws IOException {

        final EPackage[] ePackages = new EPackage[] {
                EcorePackage.eINSTANCE, IdentifierPackage.eINSTANCE, UnitsPackage.eINSTANCE,
                ProbfunctionPackage.eINSTANCE, PcmPackage.eINSTANCE,
                SeffPackage.eINSTANCE, RepositoryPackage.eINSTANCE, ParameterPackage.eINSTANCE,
                UsagemodelPackage.eINSTANCE, SystemPackage.eINSTANCE, ResourcetypePackage.eINSTANCE,
                ResourceenvironmentPackage.eINSTANCE, AllocationPackage.eINSTANCE, StoexPackage.eINSTANCE,
                CorePackage.eINSTANCE, /* CompletionsPackage.eINSTANCE, */ ReliabilityPackage.eINSTANCE,
                QosReliabilityPackage.eINSTANCE, SeffReliabilityPackage.eINSTANCE,
                KAMP4attackModificationmarksPackage.eINSTANCE, ModificationmarksPackage.eINSTANCE,
                ContextPackage.eINSTANCE, SpecificationPackage.eINSTANCE, AssemblyPackage.eINSTANCE,
                AttackerPackage.eINSTANCE, AttackSpecificationPackage.eINSTANCE };

        var resourceSet = new ResourceSetImpl();

        for (final EPackage ePackage : ePackages)
            resourceSet.getPackageRegistry().put(ePackage.getNsURI(), ePackage);

        var resourceAssembly = loadResource(resourceSet, PATH_ASSEMBLY);
        var resourceAllocation = loadResource(resourceSet, PATH_ALLOCATION);
        var resourceResource = loadResource(resourceSet, PATH_RESOURCES);
        var resourceRepository = loadResource(resourceSet, PATH_REPOSITORY);
        var resourceUsage = loadResource(resourceSet, PATH_USAGE);
        var resourceContext = loadResource(resourceSet, PATH_CONTEXT);
        var resourceAttacker = loadResource(resourceSet, PATH_ATTACKER);
        var resourceModification = loadResource(resourceSet, PATH_MODIFICATION);

        var list = new ArrayList<Resource>(resourceSet.getResources());
        for (var res : list) {
            EcoreUtil.resolveAll(res);
        }

        assembly = (System) resourceAssembly.getContents().get(0);
        environment = (ResourceEnvironment) resourceResource.getContents().get(0);
        allocation = (Allocation) resourceAllocation.getContents().get(0);
        context = (ConfidentialAccessSpecification) resourceContext.getContents().get(0);
        attacker = (AttackerSpecification) resourceAttacker.getContents().get(0);
        resourceRepository.getContents().get(0);
        resourceUsage.getContents().get(0);
        modification = (AbstractKAMP4attackModificationRepository<?>) resourceModification.getContents().get(0);
    }

    private static Resource loadResource(final ResourceSet resourceSet, final String path) {
        return resourceSet.getResource(URI.createURI(path), true);
    }

    @Test
    void test() {

        var wrapper = new BlackboardWrapper(modification, assembly, environment, allocation,
                context.getPcmspecificationcontainer());
        (new AttackPropagationAnalysis()).runChangePropagationAnalysis(wrapper);

        var steps = modification.getChangePropagationSteps();

        assertTrue(steps.stream().allMatch(e -> e instanceof CompromisedAssembly || e instanceof CredentialChange
                || e instanceof CompromisedResource));
    }

}
