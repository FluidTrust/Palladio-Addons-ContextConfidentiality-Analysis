package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.ResourceChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class PropagationResourceTest extends AbstractModelTest {
    public PropagationResourceTest() {
        this.PATH_ATTACKER = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/My.attacker";
        this.PATH_ASSEMBLY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newAssembly.system";
        this.PATH_ALLOCATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newAllocation.allocation";
        this.PATH_CONTEXT = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/My.context";
        this.PATH_MODIFICATION = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newRepository.repository";
        this.PATH_USAGE = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "platform:/plugin/edu.kit.ipd.sdq.kamp4attack.tests/models/PropagationUnitTests/newResourceEnvironment.resourceenvironment";
    }

    @Override
    void execute() {

    }

    @Test
    @Disabled //not yet finished
    void testResourceToContextPropagationNoContextsNoSpecification() {
        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var resourceChange = createResourceChange(change);
        var resource = resourceChange.getAffectedElement();

        runResourceContextPropagation(change);
        
        var components = findComponents(resource);

        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getContextchange().isEmpty());
//        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        
        assertEquals(components.size(), change.getCompromisedassembly().size());
        
        

    }

    private void runResourceContextPropagation(CredentialChange change) {
        var wrapper = getBlackboardWrapper();
        var resourceChange = new ResourceChange(wrapper);
        resourceChange.calculateResourceToContextPropagation(change);
    }

    private CompromisedResource createResourceChange(CredentialChange change) {
        var infectedResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        var resource = this.environment.getResourceContainer_ResourceEnvironment().get(0);
        infectedResource.setAffectedElement(resource);
        change.getCompromisedresource().add(infectedResource);
        return infectedResource;
    }

    private List<AssemblyContext> findComponents(ResourceContainer resource) {
        return this.allocation.getAllocationContexts_Allocation().stream()
                .filter(e -> EcoreUtil.equals(e.getResourceContainer_AllocationContext(), resource))
                .map(AllocationContext::getAssemblyContext_AllocationContext).collect(Collectors.toList());
    }

}
