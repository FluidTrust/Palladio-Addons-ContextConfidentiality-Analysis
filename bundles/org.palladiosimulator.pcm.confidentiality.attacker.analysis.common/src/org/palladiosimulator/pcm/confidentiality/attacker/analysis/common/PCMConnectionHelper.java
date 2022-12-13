package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeResourceContainerStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeTargetedConnectorsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.ChangeLinkingResourcesStorage;
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

    public static List<AssemblyContext> getConnectectedAssemblies(final System system,
            final AssemblyContext component) {
        final var targetConnectors = getConnectedConnectors(component, system);

        final var targetComponents = targetConnectors.stream()
            .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
            .filter(e -> !EcoreUtil.equals(e, component))
            .collect(Collectors.toList());
        // not possible to change to toList() since this list needs to be mutable

        targetComponents.addAll(targetConnectors.stream()
            .map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
            .filter(e -> !EcoreUtil.equals(e, component))
            .toList());
        return CollectionHelper.removeDuplicates(targetComponents);
    }

    public static List<AssemblyConnector> getConnectedConnectors(final AssemblyContext component, final System system) {
        final var storage = AssemblyContextChangeTargetedConnectorsStorage.getInstance();

        // Uses a HashMap to store results, to avoid recalculation and improve performance
        if (!storage.contains(component.getId())) {
            final var targetedConnectors = system.getConnectors__ComposedStructure()
                .stream()
                .filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .toList();
            storage.put(component.getId(), targetedConnectors);
        }

        return storage.get(component.getId());
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
    public static ResourceContainer getResourceContainer(final AssemblyContext component,
            final Allocation allocationModel) {
        final var storage = AssemblyContextChangeResourceContainerStorage.getInstance();

        // Uses a HashMap to store results, to avoid recalculation and improve
        // performance
        if (!storage.contains(component.getId())) {
            final var allocationOPT = allocationModel.getAllocationContexts_Allocation()
                .parallelStream()
                .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
                .findAny();
            if (allocationOPT.isEmpty()) {
                throw new IllegalStateException(
                        "No Allocation for assemblycontext " + component.getEntityName() + " found");
            }

            storage.put(component.getId(), allocationOPT.get()
                .getResourceContainer_AllocationContext());
        }

        return storage.get(component.getId());
    }

    public static List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource,
            final ResourceEnvironment environment) {
        final var resources = getLinkingResource(resource, environment).stream()
            .flatMap(e -> e.getConnectedResourceContainers_LinkingResource()
                .stream())
            .distinct()
            .filter(e -> !EcoreUtil.equals(e, resource))
            .collect(Collectors.toList());
        return resources;
    }

    public static List<LinkingResource> getLinkingResource(final ResourceContainer container,
            final ResourceEnvironment resourceEnvironment) {
        final var storage = ChangeLinkingResourcesStorage.getInstance();

        // Uses a HashMap to store results, to avoid recalculation and improve performance
        if (!storage.contains(container.getId())) {
            final var linkingResourcesList = resourceEnvironment.getLinkingResources__ResourceEnvironment()
                .stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource()
                    .stream()
                    .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
            storage.put(container.getId(), linkingResourcesList);
        }

        return storage.get(container.getId());
    }

}
