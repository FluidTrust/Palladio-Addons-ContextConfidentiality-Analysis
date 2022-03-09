package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;


import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.google.common.graph.EndpointPair;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdgeContent;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class Change<T> {

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;

    protected AttackGraph attackGraph;
    
    private int stackLevel;
    private AttackPathSurface selectedSurfacePath;

    public Change(final BlackboardWrapper v, final CredentialChange change, final AttackGraph attackGraph) {
        this.modelStorage = v;
        this.changes = change;
        this.attackGraph = attackGraph;
        this.stackLevel = 0;
        this.selectedSurfacePath = new AttackPathSurface();
    }

    public CredentialChange getChanges() {
        return this.changes;
    }

    protected AttackGraph getAttackGraph() {
        return this.attackGraph;
    }

    protected void updateFromContextProviderStream(final CredentialChange changes,
            final Stream<? extends PCMAttributeProvider> streamAttributeProvider) {
        final var streamContextChange = streamAttributeProvider.map(e -> {
            if (e.getAssemblycontext() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getAssemblycontext()));
            }
            if (e.getLinkingresource() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getLinkingresource()));
            }
            if (e.getResourcecontainer() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getResourcecontainer()));
            }
            return HelperUpdateCredentialChange.createContextChange(e.getAttribute(), null);
        });

        HelperUpdateCredentialChange.updateCredentials(changes, streamContextChange, null,this.attackGraph);
    }
    
    

    protected boolean isCompromised(final Entity... entities) {
        return this.attackGraph.isAnyCompromised(entities);
    }
    
    protected void callRecursionIfNecessary(final AttackStatusNodeContent childNode, 
            final Runnable recursionMethod, final AttackStatusNodeContent selectedNode) {
        selectedNode.setVisited(true);
        addChildNodeToPathIfNecessary(childNode);
        if (childNode != null && !childNode.isVisited() && !isFiltered()) {
            // select the child node and recursively call the propagation call
            this.attackGraph.setSelectedNode(childNode);
            this.stackLevel++;
            childNode.setVisited(true);
            recursionMethod.run();
            removeChildNodeFromPath();
            this.stackLevel--;
            this.attackGraph.setSelectedNode(selectedNode);
        }
    }

    private void addChildNodeToPathIfNecessary(AttackStatusNodeContent childNode) {
        final var criticalNode = this.attackGraph.getRootNodeContent();
        if (childNode != null && !childNode.isVisited()) {
            final AttackStatusEdge edge;
            final int size = this.selectedSurfacePath.size();
            if (size == 0) {
                edge = new AttackStatusEdge(new AttackStatusEdgeContent(), 
                        EndpointPair.ordered(childNode, criticalNode));
            } else {
                edge = new AttackStatusEdge(new AttackStatusEdgeContent(), 
                        EndpointPair.ordered(childNode, 
                                this.selectedSurfacePath.get(size - 1).getNodes().source()));
            }
            this.selectedSurfacePath.addFirst(edge);
        }
    }
    
    private void removeChildNodeFromPath() {
        this.selectedSurfacePath.remove(0);
    }

    private boolean isFiltered() {
        final var criticalElement = this.attackGraph.getRootNodeContent().getContainedElement();
        return AttackHandlingHelper.isFiltered(this.modelStorage, this.attackGraph, 
                this.selectedSurfacePath.toAttackPath(modelStorage, 
                        criticalElement, true));
    }

    protected ResourceContainer getResourceContainerForElement(
            final AttackStatusNodeContent selectedNodeContent) {
        final var selectedElementType = selectedNodeContent.getTypeOfContainedElement();
        final var selectedPCMElement = selectedNodeContent.getContainedElementAsPCMElement();

        final ResourceContainer ret;
        switch (selectedElementType) {
        case ASSEMBLY_CONTEXT:
            final var selectedAssembly = selectedPCMElement.getAssemblycontext();
            final var containerOfSelected = getResourceContainer(selectedAssembly);
            ret = containerOfSelected;
            break;
        case RESOURCE_CONTAINER:
            final var selectedContainer = selectedPCMElement.getResourcecontainer();
            ret = selectedContainer;
            break;
        default:
            // TODO implement all possible cases

            ret = null; // TODO
            break;
        }
        return ret;
    }

    protected ResourceContainer getResourceContainer(final AssemblyContext component) {
        final var allocationOPT = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
                .findAny();
        if (allocationOPT.isEmpty()) {
            throw new IllegalStateException(
                    "No Allocation for assemblycontext " + component.getEntityName() + " found");
        }
        return allocationOPT.get().getResourceContainer_AllocationContext();
    }
    
    protected AttackStatusNodeContent findResourceContainerNode(final ResourceContainer resourceContainer,
            final AttackStatusNodeContent selectedNode) {
        final boolean isSelectedNodeAlreadyResourceContainerNode = selectedNode
                .getContainedElement().getId()
                .equals(resourceContainer.getId());
        return isSelectedNodeAlreadyResourceContainerNode 
                    ? selectedNode
                    : this.getAttackGraph().addOrFindChild(selectedNode, new AttackStatusNodeContent(resourceContainer));
    }

    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        final var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }
}
