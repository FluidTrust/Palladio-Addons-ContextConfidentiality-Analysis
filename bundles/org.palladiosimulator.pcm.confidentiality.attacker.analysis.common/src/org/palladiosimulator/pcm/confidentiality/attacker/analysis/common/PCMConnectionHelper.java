package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

public class PCMConnectionHelper {

    private PCMConnectionHelper() {
        assert false;
    }

    public static List<AssemblyContext> getConnectectedAssemblies(System system, AssemblyContext component) {
        final var targetConnectors = getConnectedConnectors(component, system);

        final var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());
        // not possible to change to toList() since this list needs to be mutable

        targetComponents
                .addAll(targetConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
                        .filter(e -> !EcoreUtil.equals(e, component)).toList());
        return CollectionHelper.removeDuplicates(targetComponents);
    }

    public static List<AssemblyConnector> getConnectedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .toList();
    }

    /**
     * Get the resource container on which the AssemblyContext is allocated
     *
     * @param component
     *            requested AssemblyContext
     * @param allocationModel
     *            used AllocationModel
     * @return allocated ResourceContainer
     */
    public static ResourceContainer getResourceContainer(final AssemblyContext component, Allocation allocationModel) {
        final var allocationOPT = allocationModel.getAllocationContexts_Allocation().stream()
                .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
                .findAny();
        if (allocationOPT.isEmpty()) {
            throw new IllegalStateException(
                    "No Allocation for assemblycontext " + component.getEntityName() + " found");
        }
        return allocationOPT.get().getResourceContainer_AllocationContext();
    }

    public static List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource,
            ResourceEnvironment environment) {
        final var resources = getLinkingResource(resource, environment).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }

    public static List<LinkingResource> getLinkingResource(final ResourceContainer container,
            ResourceEnvironment resourceEnvironment) {
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }



}
