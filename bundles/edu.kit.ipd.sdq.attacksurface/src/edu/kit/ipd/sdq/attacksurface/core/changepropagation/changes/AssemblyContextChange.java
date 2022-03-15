package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an abstract class for an assembly context change, 
 * i.e. a propagation from assembly contexts with a certain kind of attacking.
 * 
 * @author ugnwq
 * @version 1.0
 */
public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {
    protected AssemblyContextChange(final BlackboardWrapper v, final CredentialChange change,
            final AttackGraph attackGraph) {
        super(v, change, attackGraph);
    }

    protected List<AssemblyContext> getCompromisedAssemblyContexts() {
        return this.getAttackGraph().getCompromisedNodes().stream()
                .filter(n -> n.getTypeOfContainedElement().equals(PCMElementType.ASSEMBLY_CONTEXT))
                .map(n -> n.getContainedElementAsPCMElement().getAssemblycontext()).collect(Collectors.toList());
    }
    
    protected List<AssemblyContext> getAttackedAssemblyContexts() {
        return this.getAttackGraph().getAttackedNodes().stream()
                .filter(n -> n.getTypeOfContainedElement().equals(PCMElementType.ASSEMBLY_CONTEXT))
                .map(n -> n.getContainedElementAsPCMElement().getAssemblycontext()).collect(Collectors.toList());
    }

    @Override
    public void calculateAssemblyContextToContextPropagation() {
        
    }

    @Override
    public void calculateAssemblyContextToRemoteResourcePropagation() {
        final var finalSelectedNode = this.attackGraph.getSelectedNode();
        final var relevantResourceContainer = getResourceContainerForElement(finalSelectedNode);
        final var relevantResourceContainerNode = findResourceContainerNode(relevantResourceContainer,
                finalSelectedNode);

        if (relevantResourceContainerNode != null) {
            final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
            final var allConnectedComponents = connectedResourceContainers.stream().map(this::getAllContainedAssemblies)
                    .flatMap(List::stream).collect(Collectors.toList());
            this.calculateResourceContainerPropagation(relevantResourceContainerNode, allConnectedComponents,
                    finalSelectedNode, this::calculateAssemblyContextToRemoteResourcePropagation, true);
        }
    }

    @Override
    public void calculateAssemblyContextToLocalResourcePropagation() {
        final var finalSelectedNode = this.attackGraph.getSelectedNode();
        final var relevantResourceContainer = getResourceContainerForElement(finalSelectedNode);
        final var relevantResourceContainerNode = findResourceContainerNode(relevantResourceContainer,
                finalSelectedNode);

        if (relevantResourceContainerNode != null) {
            final var containedComponents = getAllContainedAssemblies(relevantResourceContainer);
            this.calculateResourceContainerPropagation(relevantResourceContainerNode, containedComponents,
                    finalSelectedNode, this::calculateAssemblyContextToLocalResourcePropagation, false);
        }
    }

    private void calculateResourceContainerPropagation(final AttackStatusNodeContent relevantResourceContainerNode,
            final List<AssemblyContext> components, final AttackStatusNodeContent finalSelectedNode,
            final Runnable recursionCall, final boolean isRemote) {
        final var relevantResourceContainer = relevantResourceContainerNode.getContainedElementAsPCMElement()
                .getResourcecontainer();
        final var finalSelectedEntity = finalSelectedNode.getContainedElement();
        for (var component : components) {
            final var handler = isRemote ? getRemoteResourceHandler() : getLocalResourceHandler();
            handler.attackResourceContainer(List.of(relevantResourceContainer), this.changes, component);
        }

        // attack connected resource containers from the inside if the element to be
        // attacked is not yet compromised
        if (!isAnyCompromised(finalSelectedEntity)) {
            final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
            for (final var connectedContainer : connectedResourceContainers) {
                // continue building the graph
                final var childNode = this.attackGraph.addOrFindChild(relevantResourceContainerNode,
                        new AttackStatusNodeContent(connectedContainer));
                this.callRecursionIfNecessary(childNode, recursionCall, finalSelectedNode);
            }
        }
    }

    protected abstract ResourceContainerHandler getLocalResourceHandler();

    protected abstract ResourceContainerHandler getRemoteResourceHandler();

    @Override
    public void calculateAssemblyContextToAssemblyContextPropagation() {
        final var finalSelectedNode = this.attackGraph.getSelectedNode();
        final var selectedComponents = getRelevantAssemblyContexts(finalSelectedNode);
        for (var selectedComponent : selectedComponents) {
            final var selectedNode = findSelectedNode(finalSelectedNode, selectedComponents, selectedComponent);
            if (selectedNode != null) {
                handleSelectedNodePropagation(selectedNode, selectedComponent);
            }
        }
        this.attackGraph.setSelectedNode(finalSelectedNode);
    }

    /**
     * Finds the new selected node for the assembly to assembly propagation.
     * 
     * @param finalSelectedNode - the final selected nopde
     * @param selectedComponents - the list of selected components
     * @param selectedComponent - the selected component now
     * @return the new selected node, i.e. the final selected node itself if the selected components list is empty
     * or has just one element or a child node containing the selected component
     */
    private AttackStatusNodeContent findSelectedNode(AttackStatusNodeContent finalSelectedNode,
            List<AssemblyContext> selectedComponents, AssemblyContext selectedComponent) {
        if (selectedComponents.isEmpty() || selectedComponents.size() == 1) {
            return finalSelectedNode;
        }
        final var childNode = this.attackGraph.addOrFindChild(finalSelectedNode,
                new AttackStatusNodeContent(selectedComponent));
        return childNode;
    }

    /**
     * Attacks the selected comnponent by itself.
     * 
     * @param selectedNode - the selected node
     * @param selectedComponent - the selected component
     */
    private void handleSelectedNodePropagation(final AttackStatusNodeContent selectedNode,
            final AssemblyContext selectedComponent) {
        this.attackGraph.setSelectedNode(selectedNode);
        var connectedComponents = getConnectedComponents(selectedComponent);
        final var handler = getAssemblyHandler();
        handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, selectedComponent, false);
        // TODO this.handleSeff(selectedComponent);

        handleConnectedComponentsPropagation(selectedNode, selectedComponent, connectedComponents, handler);
    }

    /**
     * Attacks the connected components and calls the recursion if necessary.
     * 
     * @param selectedNode - the selected node
     * @param selectedComponent - the selected components
     * @param connectedComponents - the connected components
     * @param handler - the assembly context attack handler
     */
    private void handleConnectedComponentsPropagation(final AttackStatusNodeContent selectedNode,
            final AssemblyContext selectedComponent, final List<AssemblyContext> connectedComponents,
            final AssemblyContextHandler handler) {
        for (final var connectedComponent : connectedComponents) {
            // continue building the graph
            final var childNode = this.attackGraph.addOrFindChild(selectedNode,
                    new AttackStatusNodeContent(connectedComponent));
            if (childNode != null) {
                final var childComponent = connectedComponent;
                handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, childComponent, false);
                // select the child node and recursively call the propagation call
                this.callRecursionIfNecessary(childNode, this::calculateAssemblyContextToAssemblyContextPropagation,
                        selectedNode);
            }
        }
    }

    private List<AssemblyContext> getRelevantAssemblyContexts(AttackStatusNodeContent nodeContent) {
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
        final var finalSelectedNode = this.attackGraph.getSelectedNode();

        final var listRelevantContexts = getRelevantAssemblyContexts(finalSelectedNode).stream()
                .filter(this::isGlobalElement).collect(Collectors.toList());

        final var resourceContainer = this.getResourceContainerForElement(finalSelectedNode);
        final var resourceContainerNode = this.findResourceContainerNode(resourceContainer, finalSelectedNode);
        final var connectedContainers = getConnectedResourceContainers(resourceContainer);
        var reachableAssemblies = CollectionHelper.getAssemblyContext(connectedContainers,
                this.modelStorage.getAllocation());
        reachableAssemblies.addAll(
                CollectionHelper.getAssemblyContext(List.of(resourceContainer), this.modelStorage.getAllocation()));

        reachableAssemblies = CollectionHelper
                .removeDuplicates(reachableAssemblies);/*
                                                        * .stream() //TODO .filter(e ->
                                                        * !isCompromised(e)).collect(Collectors.toList());
                                                        */
        for (var component : listRelevantContexts) {
            final var handler = getAssemblyHandler();
            handler.attackAssemblyContext(listRelevantContexts, changes, component, false);
        }

        // recursion for attacking assemblies inside other connected containers
        if (resourceContainerNode != null) {
            for (final var container : connectedContainers) {
                final var childNode = this.findResourceContainerNode(container, finalSelectedNode);
                if (childNode != null) {
                    this.callRecursionIfNecessary(childNode,
                            this::calculateAssemblyContextToGlobalAssemblyContextPropagation, finalSelectedNode);
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
        // TODO implement
    }

}
