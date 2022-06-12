package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
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
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an abstract class for a change, i.e. a propagation attacking
 * certain kinds of elements with a certain kind of attacking.
 *
 * @author ugnwq
 * @version 1.0
 */
public abstract class Change<T> {

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;

    protected AttackGraph attackGraph;

    private int stackLevel;
    private AttackPathSurface selectedSurfacePath;

    protected Change(final BlackboardWrapper modelStorage, final CredentialChange change, final AttackGraph attackGraph) {
        this.modelStorage = modelStorage;
        this.changes = change;
        this.attackGraph = attackGraph;
        this.stackLevel = 0;
        this.selectedSurfacePath = new AttackPathSurface();
        this.attackGraph.setSelectedPath(this.selectedSurfacePath);
    }

    public CredentialChange getChanges() {
        return this.changes;
    }

    protected AttackGraph getAttackGraph() {
        return this.attackGraph;
    }

    protected boolean isAnyCompromised(final Entity... entities) {
        return this.attackGraph.isAnyCompromised(entities);
    }

    /**
     * Calls the recursion if this is necessary.
     *
     * @param childNodeContent       - the child node content
     * @param recursionMethod - the recursion method runnable
     * @param selectedNodeContent    - the selected node before and after the recursive
     *                        call
     */
    protected void callRecursionIfNecessary(final AttackStatusNodeContent childNodeContent, final Runnable recursionMethod,
            final AttackStatusNodeContent selectedNodeContent) {
        this.attackGraph.getSelectedNode().setVisited(true);
        this.attackGraph.setSelectedNode(childNodeContent);
        final var childNode = this.attackGraph.getSelectedNode();
        final var isNecessary = !childNode.isVisited();
        childNode.setVisited(true);
        if (isNecessary) {
            // recursively call the propagation call on the child node
            addChildNodeToPath(childNode);
            if (!isFiltered()) {
                this.stackLevel++;
                recursionMethod.run();
                this.stackLevel--;
            }
            removeChildNodeFromPath();
        }
        this.attackGraph.setSelectedNode(selectedNodeContent);
    }

    private void addChildNodeToPath(final AttackStatusNodeContent childNode) {
        final var criticalNode = this.attackGraph.getRootNodeContent();
        final AttackStatusEdge edge;
        final var size = this.selectedSurfacePath.size();
        if (size == 0) {
            edge = new AttackStatusEdge(new AttackStatusEdgeContent(), EndpointPair.ordered(childNode, criticalNode));
        } else {
            edge = new AttackStatusEdge(new AttackStatusEdgeContent(),
                    EndpointPair.ordered(childNode, this.selectedSurfacePath.get(0).getNodes().source()));
        }
        this.selectedSurfacePath.addFirst(edge);
    }

    private void removeChildNodeFromPath() {
        this.selectedSurfacePath.removeFirst();
    }

    private boolean isFiltered() {
        final var criticalElement = this.attackGraph.getRootNodeContent().getContainedElement();

        return AttackHandlingHelper.isFiltered(this.modelStorage,
                this.selectedSurfacePath.toAttackPath(this.modelStorage, criticalElement, true), true);
        // vulnerabilities are filtered in the AttackHandler
    }

    /**
     *
     * @param selectedNodeContent - the given node content
     * @return the resource container for the given node content, i.e. the
     *         containing resource container or the container itself
     */
    protected ResourceContainer getResourceContainerForElement(final AttackStatusNodeContent selectedNodeContent) {
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
            // TODO later implement all possible cases

            ret = null; // TODO later
            break;
        }
        return ret;
    }

    protected ResourceContainer getResourceContainer(final List<AssemblyContext> components) {
        var component = components.get(0); // TODO Fix for list;
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
        final var isSelectedNodeAlreadyResourceContainerNode = selectedNode.getContainedElement().getId()
                .equals(resourceContainer.getId());
        return isSelectedNodeAlreadyResourceContainerNode ? selectedNode
                : this.getAttackGraph().addOrFindChild(selectedNode, new AttackStatusNodeContent(resourceContainer));
    }

    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        final var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }

    /**
     *
     * @param resource - the resource container
     * @return all connected containers to the given container
     */
    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }
}
