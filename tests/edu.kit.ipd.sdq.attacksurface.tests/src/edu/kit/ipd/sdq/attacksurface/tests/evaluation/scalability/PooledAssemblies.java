package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSystemSpecificationContainer;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.resourceenvironment.ResourceenvironmentFactory;
import org.palladiosimulator.pcm.system.SystemFactory;

import org.junit.Assert;

public class PooledAssemblies extends ScalabilityTests {
    private static int id = 0;
    
    private int maximumPathLength = 1;

    @Override
    protected String getFilename() {
        return "pooledAssemblies.csv";
    }

    @Override
    protected ResourceContainer resourceAddOperation(ResourceEnvironment environment, ResourceContainer origin,
            VulnerabilitySystemIntegration integration) {
        var linking = environment.getLinkingResources__ResourceEnvironment().get(0);
        var resource = ResourceenvironmentFactory.eINSTANCE.createResourceContainer();
        
        linking.getConnectedResourceContainers_LinkingResource().add(resource);
        
        final var oldAllocation = this.allocation.getAllocationContexts_Allocation().get(0);
        final var oldAssembly = this.allocation.getAllocationContexts_Allocation().stream()
            .filter(a -> EcoreUtil.equals(a.getResourceContainer_AllocationContext(), origin))
            .map(a -> a.getAssemblyContext_AllocationContext())
            .findFirst().orElse(null);
        final var oldConnector = this.assembly.getConnectors__ComposedStructure().stream()
                .filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .findFirst().orElse(null);
        final var newAssembly = EcoreUtil.copy(oldAssembly);
        newAssembly.setId(nextId());
        newAssembly.setEntityName(newAssembly.getId() + " middle");
        final var newAllocation = EcoreUtil.copy(oldAllocation);
        newAllocation.setId(nextId());
        newAllocation.setEntityName("allocation_" + newAllocation.getId());
        newAllocation.setAssemblyContext_AllocationContext(newAssembly);
        newAllocation.setResourceContainer_AllocationContext(resource);
        this.allocation.getAllocationContexts_Allocation().add(newAllocation);
        this.assembly.getAssemblyContexts__ComposedStructure().add(newAssembly);
        final var newConnector = EcoreUtil.copy(oldConnector);
        newConnector.setRequiringAssemblyContext_AssemblyConnector(newAssembly);
        newConnector.setProvidingAssemblyContext_AssemblyConnector(oldAssembly);
        this.assembly.getConnectors__ComposedStructure().add(newConnector);
        
        var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmElement.setAssemblycontext(newAssembly);
        integration.setPcmelement(pcmElement);

        environment.getResourceContainer_ResourceEnvironment().add(resource);

        this.maximumPathLength++;
        return resource;
    }

    private static String nextId() {
        return "" + (id++);
    }

    @Override
    protected int getMaximumPathLength() {
        return this.maximumPathLength;
    }

    @Override
    protected void runEvaluationAnalysis() {
        runAssemblyAssemblyPropagationWithAttackPathGeneration(getChanges());
    }

    @Override
    protected void moveVulnerabilitiesIfNecessary(final AttackerSystemSpecificationContainer attacks) {
        // nothing needs to be done
    }

    @Override
    protected int getMaximumNumberOfAdditions() {
        return 17;
    }
}