package edu.kit.ipd.sdq.attacksurface.tests.attackhandlers;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.tests.AbstractModelTest;

public abstract class AbstractAttackHandlerTest extends AbstractModelTest {

    public AbstractAttackHandlerTest() {
        // TODO adapt
        this.PATH_ATTACKER = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.system";
        this.PATH_ALLOCATION = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.repository";
        this.PATH_USAGE = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.resourceenvironment";
    }

    protected ResourceContainer getResourceContainer(final List<AssemblyContext> componentList) {
        final var component = componentList.get(0);
        final var allocationOPT = this.getBlackboardWrapper()
            .getAllocation()
            .getAllocationContexts_Allocation()
            .stream()
            .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
            .findAny();
        if (allocationOPT.isEmpty()) {
            throw new IllegalStateException(
                    "No Allocation for assemblycontext " + component.getEntityName() + " found");
        }
        return allocationOPT.get()
            .getResourceContainer_AllocationContext();
    }

    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        final var resourceEnvironment = this.getBlackboardWrapper()
            .getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment()
            .stream()
            .filter(e -> e.getConnectedResourceContainers_LinkingResource()
                .stream()
                .anyMatch(f -> EcoreUtil.equals(f, container)))
            .collect(Collectors.toList());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource)
            .stream()
            .flatMap(e -> e.getConnectedResourceContainers_LinkingResource()
                .stream())
            .distinct()
            .filter(e -> !EcoreUtil.equals(e, resource))
            .collect(Collectors.toList());
        return resources;
    }
}
