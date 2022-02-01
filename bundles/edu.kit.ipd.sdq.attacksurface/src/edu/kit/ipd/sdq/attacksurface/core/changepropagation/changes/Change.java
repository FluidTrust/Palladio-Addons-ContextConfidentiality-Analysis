package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.attacksurface.attackdag.Node;
import edu.kit.ipd.sdq.attacksurface.attackdag.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.core.CacheLastCompromisationCausingElements;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.HelperUpdateCredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class Change<T> {

    protected Collection<T> initialMarkedItems;

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;
    
    protected AttackDAG attackDAG;

    public Change(final BlackboardWrapper v, final CredentialChange change, final AttackDAG attackDAG) {
        this.modelStorage = v;
        this.initialMarkedItems = this.loadInitialMarkedItems();
        this.changes = change;
        this.attackDAG = attackDAG;
    }

    protected abstract Collection<T> loadInitialMarkedItems();

    protected void updateFromContextProviderStream(final CredentialChange changes,
            final Stream<? extends PCMAttributeProvider> streamAttributeProvider) {
        final var streamContextChange = streamAttributeProvider
                .map(e -> {
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
    
    protected void compromise(final Node<AttackStatusDescriptorNodeContent> selectedNode) {
        selectedNode.getContent().setCompromised(true);
        generateAllFoundAttackPaths(this.attackDAG.getRootNode());
    }

    protected static boolean isCompromised(final Entity entity) {
        return CacheCompromised.instance().compromised(entity);
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
    
    protected List<List<AttackStatusDescriptorNodeContent>> generateAllFoundAttackPaths(
            final Node<AttackStatusDescriptorNodeContent> root) { // TODO also partial paths?
        List<List<AttackStatusDescriptorNodeContent>> allPaths = new ArrayList<>();
        final var rootContent = root.getContent();
        if (rootContent.isCompromised()) {
            final var childrenOfRoot = root.getChildNodes();
            for (final var childNode : childrenOfRoot) {
                allPaths.addAll(generateAllFoundAttackPaths(childNode));
            }

            if (allPaths.isEmpty()) {
                allPaths.add(new ArrayList<>(Arrays.asList(rootContent)));
            } else {
                allPaths.forEach(p -> p.add(rootContent));
            }
            // only at the end of the recursion create the actual output attack paths
            if (root.equals(this.attackDAG.getRootNode())) {
                allPaths = allPaths.stream().distinct().collect(Collectors.toList());
                for (final var path : allPaths) {
                    final var criticalElement = root.getContent().getContainedAssembly();
                    convertToAttackPath(this.modelStorage, path, toPCMElement(this.modelStorage, criticalElement, true));
                }
            }
        }
        return allPaths;
    }

    private void convertToAttackPath(final BlackboardWrapper board,
            final List<AttackStatusDescriptorNodeContent> selectedPath, final PCMElement criticalPCMElement) {
        if (!selectedPath.isEmpty()) {
            final AttackPath path = AttackerFactory.eINSTANCE.createAttackPath();
            path.setCriticalElement(criticalPCMElement);

            for (final var nodeContent : selectedPath) {
                if (nodeContent.isCompromised()) {
                    final Entity entity = nodeContent.getContainedElement();
                    final PCMElement element = toPCMElement(board, entity, false);

                    // TODO call method defined in sub-class for vuln. or something similar
                    final var systemIntegration = board.getVulnerabilitySpecification().getVulnerabilities().stream()
                            .filter(getElementIdEqualityPredicate(entity)).findAny().orElse(null);
                    if (systemIntegration != null && !contains(path, systemIntegration)) {
                        systemIntegration.setPcmelement(element);
                        path.getPath().add(systemIntegration);
                    }
                } else {
                    break; // TODO: later maybe adapt for paths with gaps
                }
            }

            final boolean isPathAlreadyThere = this.attackDAG.getAlreadyFoundPaths().contains(selectedPath);
            if (!isPathAlreadyThere) {
                this.changes.getAttackpaths().add(path);
                this.attackDAG.addAlreadyFoundPath(selectedPath);
            }
        }
    }

    protected static Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return PCMElementType.typeOf(entity).getElementIdEqualityPredicate(entity);
    }

    //TODO at the moment: only pcmElement equals is checked, not the type of the system integration found
    private static boolean contains(AttackPath path, SystemIntegration systemIntegration) {
        if (path != null && systemIntegration != null) {
            return path.getPath()
                    .stream()
                    .anyMatch(s -> pcmElementEquals(s.getPcmelement(), systemIntegration.getPcmelement()));
        }
        return false;
    }

    private static boolean pcmElementEquals(final PCMElement first, final PCMElement second) {
        final var typeFirst = PCMElementType.typeOf(first);
        final var typeSecond = PCMElementType.typeOf(second);
        if (typeFirst.equals(typeSecond)) {
            return typeFirst.getEntity(first).getId().equals(typeSecond.getEntity(second).getId());
        }
        return false;
    }

    protected static PCMElement toPCMElement(final BlackboardWrapper board, final Entity entity, final boolean isDefault) {
        final var container = board.getVulnerabilitySpecification().getVulnerabilities();
        if (container.stream().anyMatch(getElementIdEqualityPredicate(entity))) {
            final var sysIntegrations = container.stream().filter(getElementIdEqualityPredicate(entity))
                    .collect(Collectors.toList());
            final var sysIntegration = findCorrectSystemIntegration(board, sysIntegrations, isDefault);
            if (sysIntegration != null) {
                return sysIntegration.getPcmelement();
            }
        }
        //TODO look if it is created and added correctly
        final var pcmElement = PCMElementType.typeOf(entity).toPCMElement(entity);
        final var sysIntegration = PcmIntegrationFactory.eINSTANCE.createDefaultSystemIntegration(); //TODO may be credential sys integ.
        sysIntegration.setPcmelement(pcmElement);
        container.add(sysIntegration);
        return pcmElement;
    }

    private static SystemIntegration findCorrectSystemIntegration(final BlackboardWrapper board,
            final List<SystemIntegration> sysIntegrations, final boolean isDefault) {
        if (!sysIntegrations.isEmpty()) {
            if (isDefault) {
                return getDefaultOrFirst(sysIntegrations);
            }
            
            for(String id = CacheLastCompromisationCausingElements.instance().popLastCauseId(); 
                    id != null; 
                    id = CacheLastCompromisationCausingElements.instance().popLastCauseId()) {
                final String lastId = id;
                final SystemIntegration systemIntegrationById = findSystemIntegrationById(sysIntegrations, lastId);
                //TODO non-global communication
                if (systemIntegrationById != null) {
                    return systemIntegrationById;
                }
            }
            return getDefaultOrFirst(sysIntegrations);
        }
        return null; 
    }

    private static SystemIntegration findSystemIntegrationById(final List<SystemIntegration> sysIntegrations,
            final String id) {
        return sysIntegrations
                    .stream()
                    .filter(v -> id.equals(v.getIdOfContent()))
                    .findAny().orElse(null);
    }

    private static SystemIntegration getDefaultOrFirst(final List<SystemIntegration> sysIntegrations) {
        return sysIntegrations
                .stream()
                .filter(DefaultSystemIntegration.class::isInstance)
                .findAny()
                .orElse(sysIntegrations.get(0));
    }
}
