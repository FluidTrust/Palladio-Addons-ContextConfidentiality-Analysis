package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackdag.Node;
import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerChange extends Change<ResourceContainer>
        implements ResourceContainerPropagation {  
    private int stackIndex;
    
    public ResourceContainerChange(final BlackboardWrapper v, CredentialChange change, final AttackDAG attackDAG) {
        super(v, change, attackDAG);
        this.stackIndex = 0;
    }

    @Override
    protected Collection<ResourceContainer> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, ResourceContainer.class);
    }

    /*protected List<ResourceContainer> getInfectedResourceContainers() {
        return this.changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());
    }*/
    
    protected ResourceContainer getResourceContainerConnectedToElement( 
            final Node<AttackStatusDescriptorNodeContent> selectedNode) {
        //TODO maybe do not return list but only one element
        final var selectedNodeContent = selectedNode.getContent();
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
                //TODO implement all possible cases
                
                ret = null; //TODO
                break;
        }
        return ret;
    }

    @Override
    public void calculateResourceContainerToContextPropagation() {
        //TODO adapt
        /*
        final var listInfectedContainer = getInfectedResourceContainers();

        final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
                .filter(e -> listInfectedContainer.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getResourcecontainer(), f)));

        updateFromContextProviderStream(this.changes, streamAttributeProvider);*/
    }

    @Override
    public void calculateResourceContainerToRemoteAssemblyContextPropagation() { 
        final var selectedNode = this.attackDAG.getSelectedNode();
        final var selectedEntity = selectedNode.getContent().getContainedElement();
        
        final var relevantResourceContainer = getResourceContainerConnectedToElement(selectedNode);
        
        final var resources = getConnectedResourceContainers(relevantResourceContainer);
        var assemblycontext = CollectionHelper.getAssemblyContext(
                Arrays.asList(relevantResourceContainer), this.modelStorage.getAllocation());
        final var handler = getAssemblyHandler();
        assemblycontext = CollectionHelper.removeDuplicates(assemblycontext);
        for (final var resource :  resources) {
            final var childNode = selectedNode.addChild(
                    new AttackStatusDescriptorNodeContent(resource));
            if (childNode != null) {
                final boolean isNotCompromisedBefore = !isCompromised(selectedEntity);
                // attack all, so that maybe in the next iteration of assembly contexts propagation 
                // more attacks are possible
                if (isNotCompromisedBefore) { //TODO geht das auch ohne diese abfrage??
                        handler.attackAssemblyContext(assemblycontext, this.changes, resource);
                }
                if (/*isNotCompromisedBefore &&*/ isCompromised(selectedEntity)) {
                    //handleSeff(this.changes, assemblycontext, resource);
                    compromise(selectedNode);
                }

                // select the child node and recursively call the propagation call
                this.attackDAG.setSelectedNode(childNode);
                this.stackIndex++;
                this.calculateResourceContainerToRemoteAssemblyContextPropagation();
                this.stackIndex--;
                this.attackDAG.setSelectedNode(selectedNode);
            }
        }
    }

    protected abstract void handleSeff(CredentialChange changes, List<AssemblyContext> components,
            ResourceContainer source);

    protected abstract AssemblyContextHandler getAssemblyHandler();

    @Override
    public void calculateResourceContainerToLocalAssemblyContextPropagation() {
        //TODO adapt
        
        /*final var listInfectedContainer = getInfectedResourceContainers();

        for (final var resource : listInfectedContainer) {
            final var localComponents = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                    .filter(e -> EcoreUtil.equals(resource, e.getResourceContainer_AllocationContext()))
                    .map(AllocationContext::getAssemblyContext_AllocationContext)
                    .filter(e -> !CacheCompromised.instance().compromised(e));

            final var streamChanges = localComponents
                    .map(e -> HelperCreationCompromisedElements.createCompromisedAssembly(e, List.of(resource)));

            final var listChanges = streamChanges
                    .filter(e -> this.changes.getCompromisedassembly().stream()
                            .noneMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                    .collect(Collectors.toList());

            if (!listChanges.isEmpty()) {
                this.changes.getCompromisedassembly().addAll(listChanges);
                CollectionHelper.addService(listChanges, this.modelStorage.getVulnerabilitySpecification(), this.changes);
                this.changes.setChanged(true);
            }
        }*/
    }

    @Override
    public void calculateResourceContainerToResourcePropagation() {
        
    //TODO adapt
        /*final var listInfectedContainer = getInfectedResourceContainers();

        for (final var resource : listInfectedContainer) {
            final var resources = getConnectedResourceContainers(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

            final var handler = getResourceHandler();
            handler.attackResourceContainer(resources, this.changes, resource);
        }
         */
    }

    protected abstract ResourceContainerHandler getResourceHandler();

    @Override
    public void calculateResourceContainerToLinkingResourcePropagation() {
      //TODO adapt
        /*
        final var listInfectedContainer = getInfectedResourceContainers();

        for (final var resource : listInfectedContainer) {
            final var linkinResources = getLinkingResource(resource).stream()
                    .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
            final var handler = getLinkingHandler();
            handler.attackLinkingResource(linkinResources, this.changes, resource);
        }
         */
    }

    protected abstract LinkingResourceHandler getLinkingHandler();

}
