package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Role;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.DefaultSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackdag.Node;
import edu.kit.ipd.sdq.attacksurface.attackdag.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.HelperUpdateCredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class Change<T> {

    protected Collection<T> initialMarkedItems;

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;

    protected AttackDAG attackDAG;
    
    private int stackIndex;

    public Change(final BlackboardWrapper v, final CredentialChange change, final AttackDAG attackDAG) {
        this.modelStorage = v;
        this.initialMarkedItems = this.loadInitialMarkedItems();
        this.changes = change;
        this.attackDAG = attackDAG;
        this.stackIndex = 0;
    }

    protected abstract Collection<T> loadInitialMarkedItems();

    protected abstract String getLastCauseId(final Entity affectedElement);

    public CredentialChange getChanges() {
        return this.changes;
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

        HelperUpdateCredentialChange.updateCredentials(changes, streamContextChange);
    }

    protected Attacker getAttacker() {
        if (this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().get(0)
                .getAffectedElement();
    }

    protected void compromise(final Node<AttackStatusDescriptorNodeContent> selectedNode, final String causeId,
            final Node<AttackStatusDescriptorNodeContent> attackSource) {
        Objects.requireNonNull(selectedNode);
        Objects.requireNonNull(attackSource);

        selectedNode.getContent().setCompromised(true);
        selectedNode.getContent().setCauseId(causeId);
        attackSource.getContent().setAttackSourceOf(selectedNode.getContent());
        generateAllFoundAttackPaths(this.attackDAG.getRootNode());
    }

    protected static boolean isCompromised(final Entity... entities) {
        return Arrays.stream(entities).anyMatch(e -> CacheCompromised.instance().compromised(e));
    }
    
    protected void callRecursion(final Node<AttackStatusDescriptorNodeContent> childNode, 
            final Runnable recursionMethod, final Node<AttackStatusDescriptorNodeContent> selectedNode) {
        // select the child node and recursively call the propagation call
        this.attackDAG.setSelectedNode(childNode);
        this.stackIndex++;
        recursionMethod.run();
        this.stackIndex--;
        this.attackDAG.setSelectedNode(selectedNode);
    }
    
    protected ResourceContainer getResourceContainerForElement(
            final Node<AttackStatusDescriptorNodeContent> selectedNode) {
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
    
    protected Node<AttackStatusDescriptorNodeContent> getResourceContainerNode(final ResourceContainer resourceContainer,
            final Node<AttackStatusDescriptorNodeContent> selectedNode) {
        final boolean isSelectedNodeAlreadyResourceContainerNode = selectedNode.getContent()
                .getContainedElement().getId()
                .equals(resourceContainer.getId());
        return isSelectedNodeAlreadyResourceContainerNode 
                    ? selectedNode
                    : selectedNode.addOrFindChild(new AttackStatusDescriptorNodeContent(resourceContainer));
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

    protected List<AttackPathSurface> generateAllFoundAttackPaths(
            final Node<AttackStatusDescriptorNodeContent> root) { // TODO                                                                 // paths?
        List<AttackPathSurface> allPaths = new ArrayList<>();
        final var rootContent = root.getContent();
        final var childrenOfRoot = root.getChildNodes();
        for (final var childNode : childrenOfRoot) {
            final var childContent = childNode.getContent();
            allPaths.addAll(generateAllFoundAttackPaths(childNode));
        }

        // add compromised elements to the path
        if (rootContent.isCompromised()) {
            if (allPaths.isEmpty()) {
                allPaths.add(new AttackPathSurface(new ArrayList<>(Arrays.asList(root))));
            } else {
                allPaths.forEach(p -> p.add(root));
            }
        }
        
        // only at the end of the recursion create the actual output attack paths
        if (root.equals(this.attackDAG.getRootNode())) {
            for (final var path : allPaths) {
                // add the attack sources
                final var firstContent = path.get(0);
                final var childrenOfFirst = path.getNode(0).getChildNodes();
                System.out.println(firstContent + ": " + childrenOfFirst); //TODO
                for (final var childNode : childrenOfFirst) {
                    final var childContent = childNode.getContent();
                    if (childContent.isAttackSourceOf(firstContent)) {
                        allPaths.forEach(p -> p.addFirst(childNode));
                    }
                }
                
                // generate the attack paths
                final var criticalContent = root.getContent();
                final var criticalPCMElement = criticalContent.getContainedElementAsPCMElement();
                convertToAttackPath(this.modelStorage, path, criticalPCMElement);
            }
        }
        return allPaths;
    }

    private void convertToAttackPath(final BlackboardWrapper board, final AttackPathSurface selectedPath,
            final PCMElement criticalPCMElement) {
        if (!selectedPath.isEmpty()) {
            final AttackPath path = AttackerFactory.eINSTANCE.createAttackPath();
            path.setCriticalElement(criticalPCMElement);

            int index = 0;
            for (final var nodeContent : selectedPath) {
                if (nodeContent.isCompromised()) {
                    final Entity entity = nodeContent.getContainedElement();
                    final var systemIntegration = findCorrectSystemIntegration(board, entity, nodeContent.getCauseId());
                    final var element = systemIntegration.getPcmelement();
                    systemIntegration.setPcmelement(element);
                    path.getPath().add(systemIntegration);
                } else if (index == 0) { // is attack source of attacked element
                    final Entity entity = nodeContent.getContainedElement();
                    final var systemIntegration = generateDefaultSystemIntegration(entity);
                    path.getPath().add(systemIntegration);
                } else {
                    break; // TODO: later maybe adapt for paths with gaps
                }
                index++;
            }

            //TODO add attack paths that do not succeed (s.above) (??)
            final var paths = this.changes.getAttackpaths();
            if (!contains(paths, path)) {
                paths.add(path);
                this.attackDAG.addAlreadyFoundPath(selectedPath);
            }
        }
    }

    protected static Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return PCMElementType.typeOf(entity).getElementIdEqualityPredicate(entity);
    }

    private static boolean contains(final List<AttackPath> attackpaths, final AttackPath path) {
        final var pathList = path.getPath();
        final var size = pathList.size();
        for (final var nowPath : attackpaths) {
            final var nowPathList = nowPath.getPath();
            if (size != nowPathList.size()) {
                continue;
            }
            boolean isContained = true;
            for (int i = 0; i < size && isContained; i++) {
                final var pcmEql = pcmElementEquals(pathList.get(i).getPcmelement(), nowPathList.get(i).getPcmelement());
                isContained = pcmEql 
                        ? vulnerabilityClassAndInnerIdEquals(pathList.get(i), nowPathList.get(i))
                        : false;
            }
            if (isContained) {
                return true;
            }
        }
        return false;
    }

    private static boolean vulnerabilityClassAndInnerIdEquals(SystemIntegration systemIntegration,
            SystemIntegration systemIntegrationTwo) {
        return Arrays.equals(systemIntegration.getClass().getInterfaces(), 
                systemIntegration.getClass().getInterfaces())
                && Objects.equals(systemIntegration.getIdOfContent(), systemIntegrationTwo.getIdOfContent());
    }

    private static boolean pcmElementEquals(final PCMElement first, final PCMElement second) {
        final var typeFirst = PCMElementType.typeOf(first);
        final var typeSecond = PCMElementType.typeOf(second);
        if (typeFirst != null && typeFirst.equals(typeSecond)) {
            return typeFirst.getEntity(first).getId().equals(typeSecond.getEntity(second).getId());
        }
        return false;
    }

    private SystemIntegration findCorrectSystemIntegration(final BlackboardWrapper board, final Entity entity,
            String causeId) {
        final var container = board.getVulnerabilitySpecification().getVulnerabilities();
        if (container.stream().anyMatch(getElementIdEqualityPredicate(entity))) {
            final var sysIntegrations = container.stream().filter(getElementIdEqualityPredicate(entity))
                    .collect(Collectors.toList());
            final var sysIntegration = findCorrectSystemIntegration(board, sysIntegrations, causeId);
            if (sysIntegration != null) {
                return sysIntegration;
            }
        }
        // create a new default system integration if no matching was found
        return generateDefaultSystemIntegration(entity);
    }

    private SystemIntegration generateDefaultSystemIntegration(final Entity entity) {
        final var pcmElement = PCMElementType.typeOf(entity).toPCMElement(entity);
        final var sysIntegration = PcmIntegrationFactory.eINSTANCE.createDefaultSystemIntegration();
        sysIntegration.setEntityName("generated default sys integration for " + entity.getEntityName());
        sysIntegration.setPcmelement(pcmElement);
        return sysIntegration;
    }

    private SystemIntegration findCorrectSystemIntegration(final BlackboardWrapper board,
            final List<SystemIntegration> sysIntegrations, final String causeId) {
        if (!sysIntegrations.isEmpty()) {
            final SystemIntegration systemIntegrationById = findSystemIntegrationById(sysIntegrations, causeId);
            // TODO non-global communication
            if (systemIntegrationById != null) {
                return systemIntegrationById;
            }
            return getDefaultOrFirst(sysIntegrations);
        }
        return null;
    }

    private static SystemIntegration findSystemIntegrationById(final List<SystemIntegration> sysIntegrations,
            final String id) {
        return copySystemIntegration(
                sysIntegrations.stream().filter(v -> Objects.equals(id, v.getIdOfContent())).findAny().orElse(null));
    }

    private static SystemIntegration copySystemIntegration(final SystemIntegration original) {
        if (original != null) {
            final SystemIntegration sysIntegration = original.getCopyExceptElement();
            sysIntegration.setPcmelement(PCMElementType.copy(original.getPcmelement()));
            return sysIntegration;
        }
        return original;
    }

    private static SystemIntegration getDefaultOrFirst(final List<SystemIntegration> sysIntegrations) {
        return sysIntegrations.stream().filter(DefaultSystemIntegration.class::isInstance).findAny()
                .orElse(sysIntegrations.get(0));
    }
}
