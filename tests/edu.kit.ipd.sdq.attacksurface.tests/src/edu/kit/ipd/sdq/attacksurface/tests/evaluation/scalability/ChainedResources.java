package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSystemSpecificationContainer;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.resourceenvironment.ResourceenvironmentFactory;

public class ChainedResources extends ScalabilityTests {
    private static int id = 0;

    private int maximumPathLength = 1;

    // TODO adapt
    @Override
    protected String getFilename() {
        return "chainedResources.csv";
    }

    @Override
    protected ResourceContainer resourceAddOperation(ResourceEnvironment environment, ResourceContainer origin,
            VulnerabilitySystemIntegration integration) {
        var resource = EcoreUtil.copy(origin);
        resource.setId(nextId());
        resource.setEntityName(resource.getId() + " middle");
        var linking = ResourceenvironmentFactory.eINSTANCE.createLinkingResource();

        linking.getConnectedResourceContainers_LinkingResource().add(origin);
        linking.getConnectedResourceContainers_LinkingResource().add(resource);

        var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmElement.setResourcecontainer(resource);
        integration.setPcmelement(pcmElement);

        environment.getLinkingResources__ResourceEnvironment().add(linking);
        environment.getResourceContainer_ResourceEnvironment().add(resource);

        this.maximumPathLength++;
        return resource;
    }

    private static String nextId() {
        return "" + (id++);
    }

    @Override
    protected int getMaximumNumberOfAdditions() {
        return 100000;
    }

    @Override
    protected int getMaximumNumberOfAdditionsForFullAnalysis() {
        return getMaximumNumberOfAdditions();
    }

    @Override
    protected void runEvaluationAnalysis() {

        runAnalysis();

//        var graph = new AttackGraphCreation(getBlackboardWrapper());
//        VulnerabilityHelper.initializeVulnerabilityStorage(getBlackboardWrapper().getVulnerabilitySpecification());
//        var future = CompletableFuture.allOf(
//                CompletableFuture.runAsync(graph::calculateAssemblyContextToAssemblyContextPropagation),
//
//                CompletableFuture.runAsync(graph::calculateAssemblyContextToAssemblyContextPropagation),
//                CompletableFuture.runAsync(graph::calculateAssemblyContextToGlobalAssemblyContextPropagation),
//                CompletableFuture.runAsync(graph::calculateAssemblyContextToLinkingResourcePropagation),
//                CompletableFuture.runAsync(graph::calculateAssemblyContextToLocalResourcePropagation),
//                CompletableFuture.runAsync(graph::calculateAssemblyContextToRemoteResourcePropagation),
//
//                CompletableFuture.runAsync(graph::calculateLinkingResourceToAssemblyContextPropagation),
//                CompletableFuture.runAsync(graph::calculateLinkingResourceToResourcePropagation),
//
//                CompletableFuture.runAsync(graph::calculateResourceContainerToLinkingResourcePropagation),
//                CompletableFuture.runAsync(graph::calculateResourceContainerToLocalAssemblyContextPropagation),
//                CompletableFuture.runAsync(graph::calculateResourceContainerToRemoteAssemblyContextPropagation),
//                CompletableFuture.runAsync(graph::calculateResourceContainerToResourcePropagation));
//        try {
//            future.get();
//        } catch (InterruptedException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        } catch (ExecutionException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }

    }

    @Override
    protected void moveVulnerabilitiesIfNecessary(final AttackerSystemSpecificationContainer attacks) {
        // move vulnerability to resource container
        final var origin = this.environment.getResourceContainer_ResourceEnvironment().get(1);
        final var assemblyInOrigin = this.allocation.getAllocationContexts_Allocation().stream()
                .filter(a -> EcoreUtil.equals(a.getResourceContainer_AllocationContext(), origin))
                .map(AllocationContext::getAssemblyContext_AllocationContext).findFirst().orElse(null);
        moveVulnerabilities(attacks, assemblyInOrigin, origin);
    }

    @Override
    protected int getMaximumPathLength() {
        return this.maximumPathLength;
    }

    @Override
    protected int getMaximumRunValue() {
        return 20;
    }
}
