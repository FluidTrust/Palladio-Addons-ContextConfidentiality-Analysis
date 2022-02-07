package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackdag.Node;
import edu.kit.ipd.sdq.attacksurface.attackdag.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {
    protected AssemblyContextChange(final BlackboardWrapper v, final CredentialChange change,
            final AttackDAG attackDAG) {
        super(v, change, attackDAG);
    }

    @Override
    protected Collection<AssemblyContext> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, AssemblyContext.class);
    }

    protected List<AssemblyContext> getCompromisedAssemblyContexts() {
        return this.changes.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
                .collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToContextPropagation() {
        // TODO adapt

        final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
                .filter(e -> listCompromisedAssemblyContexts.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f)));

        updateFromContextProviderStream(this.changes, streamAttributeProvider);

    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        final var finalSelectedNode = this.attackDAG.getSelectedNode();
        final var relevantResourceContainer = getResourceContainerForElement(finalSelectedNode);
        final var relevantResourceContainerNode = getResourceContainerNode(relevantResourceContainer,
                finalSelectedNode);

        if (relevantResourceContainerNode != null) {
            final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
            final var allConnectedComponents = connectedResourceContainers.stream().map(this::getAllContainedAssemblies)
                    .flatMap(List::stream).collect(Collectors.toList());
            this.calculateResourceContainerPropagation(relevantResourceContainerNode, allConnectedComponents,
                    finalSelectedNode, this::calculateAssemblyContextToRemoteResourcePropagation, true);
        }
    }

    private void handleSeff(final AssemblyContext sourceComponent) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = getConnectedConnectors(sourceComponent, system);

        final var specification = targetConnectors.stream()
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), sourceComponent))
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
        this.handleSeff(this.changes, specification, sourceComponent);
    }

    protected abstract void handleSeff(CredentialChange changes, List<ServiceRestriction> services,
            AssemblyContext source);

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        final var finalSelectedNode = this.attackDAG.getSelectedNode();
        final var relevantResourceContainer = getResourceContainerForElement(finalSelectedNode);
        final var relevantResourceContainerNode = getResourceContainerNode(relevantResourceContainer,
                finalSelectedNode);

        if (relevantResourceContainerNode != null) {
            final var containedComponents = getAllContainedAssemblies(relevantResourceContainer);
            this.calculateResourceContainerPropagation(relevantResourceContainerNode, containedComponents,
                    finalSelectedNode, this::calculateAssemblyContextToLocalResourcePropagation, false);
        }
    }

    private void calculateResourceContainerPropagation(
            final Node<AttackStatusDescriptorNodeContent> relevantResourceContainerNode,
            final List<AssemblyContext> components, final Node<AttackStatusDescriptorNodeContent> finalSelectedNode,
            final Runnable recursionCall, final boolean isRemote) {
        final var relevantResourceContainer = relevantResourceContainerNode.getContent()
                .getContainedElementAsPCMElement().getResourcecontainer();
        final var finalSelectedEntity = finalSelectedNode.getContent().getContainedElement();
        for (var component : components) {
            final var handler = isRemote ? getRemoteResourceHandler() : getLocalResourceHandler();
            final var containedNode = relevantResourceContainerNode
                    .addOrFindChild(new AttackStatusDescriptorNodeContent(component));
            handler.attackResourceContainer(List.of(relevantResourceContainer), this.changes, component);
            if (containedNode != null && isCompromised(relevantResourceContainer)) { // TODO
                this.compromise(relevantResourceContainerNode, getLastCauseId(relevantResourceContainer),
                        containedNode);
            }
        }

        // attack connected resource containers from the inside if the element to be
        // attacked is not yet compromised
        if (!isCompromised(finalSelectedEntity)) {
            final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
            for (final var connectedContainer : connectedResourceContainers) {
                // continue building the DAG
                final var childNode = relevantResourceContainerNode
                        .addChild(new AttackStatusDescriptorNodeContent(connectedContainer));
                if (childNode != null) {
                    this.callRecursion(childNode, recursionCall, finalSelectedNode);
                }
            }
        }
    }

    protected abstract ResourceContainerHandler getLocalResourceHandler();

    protected abstract ResourceContainerHandler getRemoteResourceHandler();

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        final var finalSelectedNode = this.attackDAG.getSelectedNode();
        final var selectedComponents = getRelevantAssemblyContexts(finalSelectedNode.getContent());
        for (var selectedComponent : selectedComponents) {
            final var selectedNode = findSelectedNode(finalSelectedNode, selectedComponents, selectedComponent);
            if (selectedNode != null) {
                handleSelectedNodePropagation(selectedNode, selectedComponent);
            }
        }
        this.attackDAG.setSelectedNode(finalSelectedNode);
    }

    private void handleSelectedNodePropagation(final Node<AttackStatusDescriptorNodeContent> selectedNode,
            final AssemblyContext selectedComponent) {
        this.attackDAG.setSelectedNode(selectedNode);
        var connectedComponents = getConnectedComponents(selectedComponent);
        final var handler = getAssemblyHandler();
        boolean isNotCompromisedBefore = !isCompromised(selectedComponent);
        if (isNotCompromisedBefore) {
            handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, selectedComponent);
            this.handleSeff(selectedComponent);
        }

        if (isCompromised(selectedComponent)) {
            compromise(selectedNode, getLastCauseId(selectedComponent), selectedNode);
        }

        handleConnectedComponentsPropagation(selectedNode, selectedComponent, isNotCompromisedBefore,
                connectedComponents, handler);
    }

    private void handleConnectedComponentsPropagation(final Node<AttackStatusDescriptorNodeContent> selectedNode,
            final AssemblyContext selectedComponent, final boolean isNotCompromisedBefore,
            final List<AssemblyContext> connectedComponents, final AssemblyContextHandler handler) {
        for (final var connectedComponent : connectedComponents) {
            // continue building the DAG
            final var childNode = selectedNode.addChild(new AttackStatusDescriptorNodeContent(connectedComponent));
            if (childNode != null) {
                final var childComponent = connectedComponent;
                if (isNotCompromisedBefore) {
                    handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, childComponent);
                    this.handleSeff(childComponent);
                }
                if (isCompromised(selectedComponent)) {
                    compromise(selectedNode, getLastCauseId(selectedComponent), childNode);
                }

                // select the child node and recursively call the propagation call
                this.callRecursion(childNode, this::calculateAssemblyContextToAssemblyContextPropagation, selectedNode);
            }
        }
    }

    private Node<AttackStatusDescriptorNodeContent> findSelectedNode(
            Node<AttackStatusDescriptorNodeContent> finalSelectedNode, List<AssemblyContext> selectedComponents,
            AssemblyContext selectedComponent) {
        if (selectedComponents.isEmpty() || selectedComponents.size() == 1) {
            return finalSelectedNode;
        }
        final var childNode = finalSelectedNode.addChild(new AttackStatusDescriptorNodeContent(selectedComponent));
        return childNode;
    }

    private List<AssemblyContext> getRelevantAssemblyContexts(AttackStatusDescriptorNodeContent nodeContent) { // TODO
                                                                                                               // rename
        final List<AssemblyContext> assemblies = new ArrayList<>();

        switch (nodeContent.getTypeOfContainedElement()) {
        case ASSEMBLY_CONTEXT:
            assemblies.add(nodeContent.getContainedElementAsPCMElement().getAssemblycontext());
            break;
        case RESOURCE_CONTAINER:
            assemblies.addAll(
                    getAllContainedAssemblies(nodeContent.getContainedElementAsPCMElement().getResourcecontainer()));
            break;
        default:
            // TODO implement other cases if necessary
            break;
        }

        return assemblies;
    }

    private List<AssemblyContext> getAllContainedAssemblies(final ResourceContainer resourcecontainer) {
        return this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(a -> EcoreUtil.equals(a.getResourceContainer_AllocationContext(), resourcecontainer))
                .map(AllocationContext::getAssemblyContext_AllocationContext).collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToGlobalAssemblyContextPropagation() {
        final var finalSelectedNode = this.attackDAG.getSelectedNode();

        final var listRelevantContexts = getRelevantAssemblyContexts(finalSelectedNode.getContent()).stream()
                .filter(this::isGlobalElement).collect(Collectors.toList());

        final var resourceContainer = this.getResourceContainerForElement(finalSelectedNode);
        final var resourceContainerNode = this.getResourceContainerNode(resourceContainer, finalSelectedNode);
        final var connectedContainers = getConnectedResourceContainers(resourceContainer);
        var reachableAssemblies = CollectionHelper.getAssemblyContext(connectedContainers,
                this.modelStorage.getAllocation());
        reachableAssemblies.addAll(
                CollectionHelper.getAssemblyContext(List.of(resourceContainer), this.modelStorage.getAllocation()));

        reachableAssemblies = CollectionHelper.removeDuplicates(reachableAssemblies).stream()
                .filter(e -> !isCompromised(e)).collect(Collectors.toList());
        for (var component : listRelevantContexts) {
            final var componentNode = finalSelectedNode
                    .addOrFindChild(new AttackStatusDescriptorNodeContent(component));
            if (componentNode != null) {
                final var handler = getAssemblyHandler();
                handler.attackAssemblyContext(reachableAssemblies, this.changes, component);
                for (final var assembly : reachableAssemblies) {
                    final var assemblyNode = componentNode
                            .addOrFindChild(new AttackStatusDescriptorNodeContent(assembly));
                    if (isCompromised(assembly)) {
                        compromise(assemblyNode, getLastCauseId(assembly), componentNode);
                    }
                }

                var listServices = CollectionHelper.getProvidedRestrictions(reachableAssemblies).stream()
                        .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
                handleSeff(this.changes, listServices, component);
            }
        }

        // recursion for attacking assemblies inside other connected containers
        if (resourceContainerNode != null) {
            for (final var container : connectedContainers) {
                final var childNode = this.getResourceContainerNode(container, finalSelectedNode);
                if (childNode != null) {
                    this.callRecursion(childNode, this::calculateAssemblyContextToGlobalAssemblyContextPropagation,
                            finalSelectedNode);
                }
            }
        }
    }

    private boolean isGlobalElement(AssemblyContext assemblyContext) {
        return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream().filter(
                systemElement -> EcoreUtil.equals(systemElement.getPcmelement().getAssemblycontext(), assemblyContext))
                .noneMatch(NonGlobalCommunication.class::isInstance);
    }

    private List<AssemblyContext> getConnectedComponents(AssemblyContext component) {
        final var system = this.modelStorage.getAssembly();

        final var connectedConnectors = getConnectedConnectors(component, system);

        final List<AssemblyContext> connectedComponents = new ArrayList<>();
        connectedComponents.addAll(
                connectedConnectors.stream().map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
                        .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList()));

        connectedComponents.addAll(
                connectedConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
                        .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList()));

        return CollectionHelper.removeDuplicates(connectedComponents);
    }

    private List<AssemblyConnector> getConnectedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .collect(Collectors.toList());
    }

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateAssemblyContextToLinkingResourcePropagation() {
        // TODO adapt

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
