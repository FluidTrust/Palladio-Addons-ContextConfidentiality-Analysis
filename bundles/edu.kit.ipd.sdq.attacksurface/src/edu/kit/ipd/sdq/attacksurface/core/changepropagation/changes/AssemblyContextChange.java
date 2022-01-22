package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
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
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.Change;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {
    private AttackDAG attackDAG;
    
    protected AssemblyContextChange(final BlackboardWrapper v, final CredentialChange change, final AttackDAG attackDAG) {
        super(v, change);
        this.attackDAG = attackDAG;
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

    private void handleSeff(final AssemblyContext sourceComponent) {
        final var system = this.modelStorage.getAssembly();
        // TODO simplify stream expression directly to components!
        final var targetConnectors = getSourcedConnectors(sourceComponent, system);

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
        final var criticalAssembly = this.attackDAG.getRootNode().getContent().getContainedAssembly();
        
        final var selectedNode = this.attackDAG.getSelectedNode();
        final var selectedComponent = selectedNode.getContent().getContainedAssembly();
        var sourceComponents = getConnectedComponents(selectedComponent)/*.stream()
                   .filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList())*/; //TODO
        AttackPath path = null;
        for (final var sourceComponent : sourceComponents) {
            final var handler = getAssemblyHandler();
            handler.attackAssemblyContext(Arrays.asList(selectedComponent), this.changes, sourceComponent); //TODO
            this.handleSeff(sourceComponent);
            
            // continue building the DAG
            final var childNode = selectedNode.addChild(new AttackStatusDescriptorNodeContent(sourceComponent));
            
            //TODO do not allow circles!!
            // select the child node and recursively call the propagation call if the selectedComponent is not yet attacked
            if (!CacheCompromised.instance().compromised(selectedComponent)) {
                this.attackDAG.setSelectedNode(childNode);
                this.calculateAssemblyContextToAssemblyContextPropagation();
                this.attackDAG.setSelectedNode(selectedNode);
            } else {
                //handle AttackPath addition //TODO connection DAG <--> path!
                path = addToAttackPathIfNecessary(this.modelStorage, this.changes, 
                            path, selectedComponent, toPCMElement(criticalAssembly)); //TODO this is not correct like this
            }
        }
    }
    
    private static PCMElement toPCMElement(final AssemblyContext assembly) {
        final var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmElement.setAssemblycontext(assembly);
        return pcmElement;
    }
    
    private static AttackPath addToAttackPathIfNecessary(final BlackboardWrapper board, final CredentialChange changes,
            final AttackPath pathArg, final Entity entity, final PCMElement criticalPCMElement) {
        AttackPath path = pathArg;
        if (CacheCompromised.instance().compromised(entity)) {
            if (path == null) {
                path = KAMP4attackModificationmarksFactory.eINSTANCE.createAttackPath();
                path.setCriticalElement(criticalPCMElement);
            }
            //TODO later: find out which vuln. lead to it somehow and set the vulnerability respectively
            final var systemIntegration = board.getVulnerabilitySpecification().getVulnerabilities()
                    .stream()
                    .filter(getElementIdEqualityPredicate(entity))
                    .findAny()
                    .orElse(null);
            if (systemIntegration != null) {
                systemIntegration.setPcmelement(path.getCriticalElement());
                path.getPath().add(systemIntegration);
                if (pathArg == null) {
                    changes.getAttackpaths().add(path);
                }
                return path;
            }
        }
        return null;
    }
    
    private static Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return s -> {
            final Set<String> ids = new HashSet<>();
            final var pcmElement = s.getPcmelement();
            ids.add(pcmElement.getAssemblycontext().getId());
            //TODO adapt for other entity types as well and also check for null before!
            return ids.contains(entity.getId());
        };
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
        final var sourceConnectors = getSourcedConnectors(component, system);

        final var sourceComponents = sourceConnectors
                .stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component))
                .distinct() //TODO geht das so?
                .collect(Collectors.toList());
        /* TODO remove v (s.u.)
          final var sourceComponents = sourceConnectors.stream()
                .map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());

        sourceComponents
            .addAll(sourceConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList()));*/
        return sourceComponents;
    }

    private List<AssemblyConnector> getSourcedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        /*|| EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component)*/) //TODO providing too?
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
