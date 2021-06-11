package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.ProvidedRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {

    protected AssemblyContextChange(final BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<AssemblyContext> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, AssemblyContext.class);
    }

    protected List<AssemblyContext> getCompromisedAssemblyContexts(final CredentialChange changes) {
        final var listCompromisedAssemblyContexts = changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());
        return listCompromisedAssemblyContexts;
    }

    @Override
    public void calculateAssemblyContextToContextPropagation(final CredentialChange changes) {
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts(changes);

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f)));

        updateFromContextProviderStream(changes, streamAttributeProvider);

    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation(final CredentialChange changes) {
        final var listCompromisedContexts = getCompromisedAssemblyContexts(changes);

        for (final var component : listCompromisedContexts) {
            final var connected = getConnectedComponents(component);
            final var containers = connected.stream().map(this::getResourceContainer).distinct()
                    .collect(Collectors.toList());
            final var handler = getRemoteResourceHandler();
            handler.attackResourceContainer(containers, changes, component);
        }

    }

    private void handleSeff(CredentialChange changes, AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = getTargetedConnectors(component, system);

        final var specification = targetConnectors.stream()
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component))
                .map(role -> {
                    var methodspecification = AssemblyFactory.eINSTANCE.createProvidedRestriction();
                    methodspecification.setAssemblycontext(role.getProvidingAssemblyContext_AssemblyConnector());
                    methodspecification.setProvidedrole(role.getProvidedRole_AssemblyConnector());
                    return methodspecification;
                }).collect(Collectors.toList());
        handleSeff(changes, specification, component);
    }

    protected abstract void handleSeff(CredentialChange changes, List<ProvidedRestriction> components,
            AssemblyContext source);

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation(final CredentialChange changes) {
        final var listCompromisedContexts = getCompromisedAssemblyContexts(changes);

        for (final var component : listCompromisedContexts) {
            final var resource = getResourceContainer(component);
            final var handler = getLocalResourceHandler();
            handler.attackResourceContainer(List.of(resource), changes, component);
        }

    }

    private ResourceContainer getResourceContainer(final AssemblyContext component) {
        final var allocationOPT = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
                .findAny();
        if (allocationOPT.isEmpty()) {
            throw new IllegalStateException(
                    "No Allocation for assemblycontext " + component.getEntityName() + " found");
        }
        final var resource = allocationOPT.get().getResourceContainer_AllocationContext();
        return resource;
    }

    protected abstract ResourceContainerHandler getLocalResourceHandler();

    protected abstract ResourceContainerHandler getRemoteResourceHandler();

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation(final CredentialChange changes) {
        final var listCompromisedContexts = getCompromisedAssemblyContexts(changes);
        for (final var component : listCompromisedContexts) {
            var targetComponents = getConnectedComponents(component);

            final var handler = getAssemblyHandler();
            targetComponents = CollectionHelper.removeDuplicates(targetComponents);
            handler.attackAssemblyContext(targetComponents, changes, component);
            handleSeff(changes, component);
        }

    }

    private List<AssemblyContext> getConnectedComponents(final AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = getTargetedConnectors(component, system);

        final var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());

        targetComponents
                .addAll(targetConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
                        .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList()));
        return targetComponents;
    }

    private List<AssemblyConnector> getTargetedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .collect(Collectors.toList());
    }

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation(final CredentialChange changes) {
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts(changes);

        for (final var component : listCompromisedAssemblyContexts) {
            final var resource = getResourceContainer(component);
            final var reachableLinkingResources = getLinkingResource(resource);
            final var handler = getLinkingHandler();
            handler.attackLinkingResource(reachableLinkingResources, changes, component);
        }
    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
