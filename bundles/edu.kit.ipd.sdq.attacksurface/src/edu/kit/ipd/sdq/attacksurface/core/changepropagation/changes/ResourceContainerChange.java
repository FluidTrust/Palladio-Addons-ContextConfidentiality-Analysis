package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an abstract class for a resource container change, 
 * i.e. a propagation from resource containers with a certain kind of attacking.
 * 
 * @author ugnwq
 * @version 1.0
 */
public abstract class ResourceContainerChange extends Change<ResourceContainer>
        implements ResourceContainerPropagation {
    protected ResourceContainerChange(final BlackboardWrapper modelStorage, CredentialChange change, final AttackGraph attackGraph) {
        super(modelStorage, change, attackGraph);
    }

    protected List<ResourceContainer> getInfectedResourceContainers() {
        return this.getAttackGraph().getCompromisedNodes().stream()
                .filter(n -> n.getTypeOfContainedElement().equals(PCMElementType.RESOURCE_CONTAINER))
                .map(n -> n.getContainedElementAsPCMElement().getResourcecontainer()).collect(Collectors.toList());
    }

    @Override
    public void calculateResourceContainerToContextPropagation() {
        
    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
        final var listInfectedContainers = getInfectedResourceContainers();

        final var selectedNode = this.attackGraph.getSelectedNode();

        final var relevantResourceContainer = getResourceContainerForElement(selectedNode);
        if (listInfectedContainers.contains(relevantResourceContainer)) {

            final var resources = getConnectedResourceContainers(relevantResourceContainer);
            var assemblycontext = CollectionHelper.getAssemblyContext(Arrays.asList(relevantResourceContainer),
                    this.modelStorage.getAllocation());
            final var handler = getAssemblyHandler();
            assemblycontext = CollectionHelper.removeDuplicates(assemblycontext);
            for (final var resource : resources) {
                final var childNode = this.attackGraph.addOrFindChild(selectedNode,
                        new AttackStatusNodeContent(resource));
                if (childNode != null) {
                    // attack all, so that maybe in the next iteration of assembly contexts
                    // propagation
                    // more attacks are possible

                    handler.attackAssemblyContext(assemblycontext, this.changes, resource, false);

                    // select the child node and recursively call the propagation call
                    this.callRecursionIfNecessary(childNode,
                            this::calculateResourceContainerToRemoteAssemblyContextPropagation, selectedNode);
                }
            }
        }
    }

    protected abstract AssemblyContextHandler getAssemblyHandler();

    // attack inner assemblies from already compromised res. containers
    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() {
        final var selectedNode = this.attackGraph.getSelectedNode();

        final var relevantResourceContainer = getResourceContainerForElement(selectedNode);
        final var resourceContainerNode = findResourceContainerNode(relevantResourceContainer, selectedNode);
        final var listInfectedContainers = getInfectedResourceContainers();
        if (listInfectedContainers.contains(relevantResourceContainer)) {
            final var localComponents = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                    .filter(e -> EcoreUtil.equals(relevantResourceContainer,
                            e.getResourceContainer_AllocationContext()))
                    .map(AllocationContext::getAssemblyContext_AllocationContext).collect(Collectors.toList());

            localComponents.forEach(c -> {
                final var newNode = new AttackStatusNodeContent(c);
                if (this.attackGraph.findNode(newNode) == null) {
                    this.attackGraph.addOrFindChild(resourceContainerNode, newNode);
                }
            });
            
            final var handler = getAssemblyHandler();
            handler.attackAssemblyContext(localComponents, this.changes, relevantResourceContainer, true);

            final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
            for (final var resource : connectedResourceContainers) {
                final var childNode = this.attackGraph.addOrFindChild(selectedNode,
                        new AttackStatusNodeContent(resource));
                this.callRecursionIfNecessary(childNode,
                        this::calculateResourceContainerToLocalAssemblyContextPropagation, selectedNode);
            }
        }
    }

    private void selfAttack(final ResourceContainer relevantResourceContainer) {
        final var handler = getResourceHandler();
        handler.attackResourceContainer(Arrays.asList(relevantResourceContainer), this.changes,
                relevantResourceContainer);
    }

    @Override
    public void calculateResourceContainerToResourcePropagation() {
        final var selectedNode = this.attackGraph.getSelectedNode();

        final var relevantResourceContainer = getResourceContainerForElement(selectedNode);
        findResourceContainerNode(relevantResourceContainer, selectedNode);
        selfAttack(relevantResourceContainer);

        final var handler = getResourceHandler();
        final var connectedResourceContainers = getConnectedResourceContainers(relevantResourceContainer);
        for (final var resource : connectedResourceContainers) {
            final var childNode = findResourceContainerNode(resource, selectedNode);
            if (childNode != null) {
                handler.attackResourceContainer(Arrays.asList(relevantResourceContainer), this.changes, resource);

                // select the child node and recursively call the propagation call
                this.callRecursionIfNecessary(childNode, this::calculateResourceContainerToResourcePropagation,
                        selectedNode);
            }
        }
    }

    protected abstract ResourceContainerHandler getResourceHandler();

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation() {
        //TODO later implement
    }

}
