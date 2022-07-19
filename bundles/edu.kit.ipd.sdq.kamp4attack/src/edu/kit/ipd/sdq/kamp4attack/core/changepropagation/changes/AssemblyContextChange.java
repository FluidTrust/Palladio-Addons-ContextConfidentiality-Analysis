package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.PCMConnectionHelper;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagationWithContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextChange extends Change<AssemblyContext>
        implements AssemblyContextPropagationWithContext {

    protected AssemblyContextChange(final BlackboardWrapper v, CredentialChange change) {
        super(v, change);
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
            final var connected = PCMConnectionHelper.getConnectectedAssemblies(this.modelStorage.getAssembly(),
                    component);
            var containers = connected.stream()
                    .map(e -> PCMConnectionHelper.getResourceContainer(e, this.modelStorage.getAllocation())).distinct()
                    .collect(Collectors.toList());

            containers.addAll(PCMConnectionHelper.getConnectedResourceContainers(
                    PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation()),
                    this.modelStorage.getResourceEnvironment()));

            containers = CollectionHelper.removeDuplicates(containers);

            final var handler = getRemoteResourceHandler();
            handler.attackResourceContainer(containers, this.changes, component);
        }

    }

    private void handleSeff(final AssemblyContext soureComponent) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = PCMConnectionHelper.getConnectedConnectors(soureComponent, system);

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
                                            .createServiceSpecification();
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

    protected abstract void handleSeff(CredentialChange changes, List<ServiceSpecification> services,
            AssemblyContext source);

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        final var listCompromisedContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedContexts) {
            final var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
            final var handler = getLocalResourceHandler();
            handler.attackResourceContainer(List.of(resource), this.changes, component);
        }

    }



    protected abstract ResourceContainerHandler getLocalResourceHandler();

    protected abstract ResourceContainerHandler getRemoteResourceHandler();

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        final var listCompromisedContexts = getCompromisedAssemblyContexts();
        for (final var component : listCompromisedContexts) {
            var targetComponents = PCMConnectionHelper
                    .getConnectectedAssemblies(this.modelStorage.getAssembly(), component).stream()
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
            var resourceContainer = PCMConnectionHelper.getResourceContainer(component,
                    this.modelStorage.getAllocation());
            var connectedContainers = getConnectedResourceContainers(resourceContainer);
            var reachableAssemblies = CollectionHelper.getAssemblyContext(connectedContainers,
                    this.modelStorage.getAllocation());
            reachableAssemblies.addAll(
                    CollectionHelper.getAssemblyContext(List.of(resourceContainer), this.modelStorage.getAllocation()));
            final var handler = getAssemblyHandler();

            // Filter duplicates, cached and non Global Components
            reachableAssemblies = CollectionHelper.removeDuplicates(reachableAssemblies).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).filter(this::isGlobalElement)
                    .collect(Collectors.toList());
            handler.attackAssemblyContext(reachableAssemblies, this.changes, component);

            var listServices = CollectionHelper.getProvidedRestrictions(reachableAssemblies).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            handleSeff(this.changes, listServices, component);
        }

    }

    private boolean isGlobalElement(AssemblyContext assemblyContext) {
        // TODO adapt get(0) for list comparision
        return CollectionHelper.isGlobalCommunication(assemblyContext,
                this.modelStorage.getVulnerabilitySpecification().getVulnerabilities());
    }

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

        for (final var component : listCompromisedAssemblyContexts) {
            final var resource = PCMConnectionHelper.getResourceContainer(component, this.modelStorage.getAllocation());
            final var reachableLinkingResources = getLinkingResource(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            final var handler = getLinkingHandler();
            handler.attackLinkingResource(reachableLinkingResources, this.changes, component);
        }
    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
