package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

public abstract class PooledResources extends ScalabilityTests {
//    private static int id = 0;
//
//    private int maximumPathLength = 1;
//
//    @Override
//    protected String getFilename() {
//        return "pooledResources.csv";
//    }
//
//    @Override
//    protected ResourceContainer resourceAddOperation(ResourceEnvironment environment, ResourceContainer origin,
//            VulnerabilitySystemIntegration integration) {
//        var linking = environment.getLinkingResources__ResourceEnvironment().get(0);
//        var resource = EcoreUtil.copy(origin);
//        resource.setId(nextId());
//        resource.setEntityName(resource.getId() + " middle");
//
//        linking.getConnectedResourceContainers_LinkingResource().add(resource);
//
//        var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
//        pcmElement.setResourcecontainer(resource);
//        integration.setPcmelement(pcmElement);
//
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
//    protected int getMaximumPathLength() {
//        return this.maximumPathLength;
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
//    protected int getMaximumNumberOfAdditions() {
//        return MAX_NUMBER_COMPLETE;
//    }
//
//    @Override
//    protected int getMaximumRunValue() {
//        return 9;
//    }
}
