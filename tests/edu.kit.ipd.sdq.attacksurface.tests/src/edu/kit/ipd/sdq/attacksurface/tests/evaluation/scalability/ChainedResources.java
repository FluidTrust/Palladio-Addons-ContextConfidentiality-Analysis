package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

public abstract class ChainedResources extends ScalabilityTests {
//    private static int id = 0;
//
//    private int maximumPathLength = 1;
//
//    //TODO adapt
//    @Override
//    protected String getFilename() {
//        return "chainedResources.csv";
//    }
//
//    @Override
//    protected ResourceContainer resourceAddOperation(ResourceEnvironment environment, ResourceContainer origin,
//            VulnerabilitySystemIntegration integration) {
//        var resource = EcoreUtil.copy(origin);
//        resource.setId(nextId());
//        resource.setEntityName(resource.getId() + " middle");
//        var linking = ResourceenvironmentFactory.eINSTANCE.createLinkingResource();
//
//        linking.getConnectedResourceContainers_LinkingResource().add(origin);
//        linking.getConnectedResourceContainers_LinkingResource().add(resource);
//
//        var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
//        pcmElement.setResourcecontainer(resource);
//        integration.setPcmelement(pcmElement);
//
//        environment.getLinkingResources__ResourceEnvironment().add(linking);
//        environment.getResourceContainer_ResourceEnvironment().add(resource);
//
//        this.maximumPathLength++;
//        return resource;
//    }
//
//    private static String nextId() {
//        return "" + (id++);
//    }
//
//    @Override
//    protected int getMaximumNumberOfAdditions() {
//        return 15;
//    }
//
//    @Override
//    protected int getMaximumNumberOfAdditionsForFullAnalysis() {
//        return getMaximumNumberOfAdditions();
//    }
//
//    @Override
//    protected void runEvaluationAnalysis() {
//        runResourceResourcePropagationWithAttackPathGeneration(getChanges());
//    }
//
//    @Override
//    protected void moveVulnerabilitiesIfNecessary(final AttackerSystemSpecificationContainer attacks) {
//        // move vulnerability to resource container
//        final var origin = environment.getResourceContainer_ResourceEnvironment().get(1);
//        final var assemblyInOrigin = this.allocation.getAllocationContexts_Allocation()
//                .stream()
//                .filter(a -> EcoreUtil.equals(a.getResourceContainer_AllocationContext(), origin))
//                .map( a -> a.getAssemblyContext_AllocationContext())
//                .findFirst().orElse(null);
//        moveVulnerabilities(attacks, assemblyInOrigin, origin);
//    }
//
//    @Override
//    protected int getMaximumPathLength() {
//        return this.maximumPathLength;
//    }
//
//    @Override
//    protected int getMaximumRunValue() {
//        return 20;
//    }
}
