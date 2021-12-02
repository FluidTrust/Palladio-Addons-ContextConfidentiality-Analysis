package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {

    protected AssemblyContextChange(final BlackboardWrapper v, CredentialChange change) {
        super(v, change);
    }

    @Override
    protected Collection<AssemblyContext> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, AssemblyContext.class);
    }

    protected List<AssemblyContext> getCompromisedAssemblyContexts() {
        return this.changes.getCompromisedassembly().stream()
                .map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToContextPropagation() {
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
                .filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f)));

        updateFromContextProviderStream(this.changes, streamAttributeProvider);

    }


    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        final var listCompromisedContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedContexts) {
            final var connected = getConnectedComponents(component);
            final var containers = connected.stream().map(this::getResourceContainer).distinct()
                    .collect(Collectors.toList());
            final var handler = getRemoteResourceHandler();
            handler.attackResourceContainer(containers, this.changes, component);
        }

    }

    private void handleSeff(final AssemblyContext soureComponent) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = getTargetedConnectors(soureComponent, system);

        final var specification = targetConnectors.stream()
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), soureComponent))
                .flatMap(role -> {

                    final var signatures = role.getProvidedRole_AssemblyConnector()
                            .getProvidedInterface__OperationProvidedRole().getSignatures__OperationInterface();

                    final var componentRepository = role.getProvidingAssemblyContext_AssemblyConnector()
                            .getEncapsulatedComponent__AssemblyContext();

                    if (componentRepository instanceof BasicComponent) {
                        final var basicComponent = (BasicComponent) componentRepository;
                        return basicComponent.getServiceEffectSpecifications__BasicComponent().stream()
                                .filter(seff -> signatures.stream().anyMatch( // find only seff of
                                        // role
                                        signature -> EcoreUtil.equals(signature, seff.getDescribedService__SEFF())))

                                .map(seff -> {
                                    final var methodspecification = StructureFactory.eINSTANCE
                                            .createServiceRestriction();
                                    methodspecification
                                    .setAssemblycontext(role.getProvidingAssemblyContext_AssemblyConnector());
                                    methodspecification.setService((ResourceDemandingSEFF) seff);
                                    methodspecification
                                    .setSignature(methodspecification.getService().getDescribedService__SEFF());
                                    return methodspecification;
                                });

                    }
                    return Stream.empty();
                }).collect(Collectors.toList());
        this.handleSeff(this.changes, specification, soureComponent);
    }

    protected abstract void handleSeff(CredentialChange changes, List<ServiceRestriction> services,
            AssemblyContext source);

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        final var listCompromisedContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedContexts) {
            final var resource = getResourceContainer(component);
            final var handler = getLocalResourceHandler();
            handler.attackResourceContainer(List.of(resource), this.changes, component);
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
        return allocationOPT.get().getResourceContainer_AllocationContext();
    }

    protected abstract ResourceContainerHandler getLocalResourceHandler();

    protected abstract ResourceContainerHandler getRemoteResourceHandler();

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        final var listCompromisedContexts = getCompromisedAssemblyContexts();
        for (final var component : listCompromisedContexts) {
            var targetComponents = getConnectedComponents(component).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

            final var handler = getAssemblyHandler();
            targetComponents = CollectionHelper.removeDuplicates(targetComponents).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            handler.attackAssemblyContext(targetComponents, this.changes, component);
            this.handleSeff(component);
        }

    }

    @Override
    public void calculateAssemblyContextToGlobalAssemblyContextPropagation() {
        final var listCompromisedContexts = getCompromisedAssemblyContexts().stream()
                .filter(this::isGlobalElement).collect(Collectors.toList());

        for (var component : listCompromisedContexts) {
            var resourceContainer = getResourceContainer(component);
            var connectedContainers = getConnectedResourceContainers(resourceContainer);
            var reachableAssemblies = CollectionHelper.getAssemblyContext(connectedContainers,
                    this.modelStorage.getAllocation());
            reachableAssemblies.addAll(
                    CollectionHelper.getAssemblyContext(List.of(resourceContainer), this.modelStorage.getAllocation()));
            final var handler = getAssemblyHandler();
            reachableAssemblies = CollectionHelper.removeDuplicates(reachableAssemblies).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            handler.attackAssemblyContext(reachableAssemblies, this.changes, component);

            var listServices = CollectionHelper.getProvidedRestrictions(reachableAssemblies).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            handleSeff(this.changes, listServices, component);
        }

    }

    private boolean isGlobalElement(AssemblyContext assemblyContext) {
        return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream().filter(
                systemElement -> EcoreUtil.equals(systemElement.getPcmelement().getAssemblycontext(), assemblyContext))
                .noneMatch(NonGlobalCommunication.class::isInstance);
    }

    private List<AssemblyContext> getConnectedComponents(final AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();
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
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedAssemblyContexts) {
            final var resource = getResourceContainer(component);
            final var reachableLinkingResources = getLinkingResource(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            final var handler = getLinkingHandler();
            handler.attackLinkingResource(reachableLinkingResources, this.changes, component);
        }
    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
