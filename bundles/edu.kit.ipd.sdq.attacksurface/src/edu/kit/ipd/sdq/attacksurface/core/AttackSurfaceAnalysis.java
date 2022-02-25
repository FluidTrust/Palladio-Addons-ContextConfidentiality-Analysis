package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.DefaultSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Entry point for attack surface propagation
 *
 * @author majuwa
 * @author ugnwq
 */

@Component
public class AttackSurfaceAnalysis {

    private CredentialChange changePropagationDueToCredential;
    
    private Entity crtitcalEntity; 
    
    private AttackGraph attackGraph;

    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance().clearCache();
        //TODO remove: CacheVulnerability.instance().reset();
        
        // prepare
        createInitialStructure(board);
        this.attackGraph = new AttackGraph(this.crtitcalEntity);
        
        //TODO adapt
        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            this.attackGraph.resetVisitations();
            
            calculateAndMarkAssemblyPropagation(board); //TODO 2. add other kinds of analysis
            //calculateAndMarkResourcePropagation(board); //TODO 1. adapt implementation
            
            
            /*TODO calculateAndMarkLinkingPropagation(board);*/
        } while (this.changePropagationDueToCredential.isChanged()); 
        
        // create all attack paths
        this.attackGraph.resetVisitations();
        final var allAttackPathsSurface = this.attackGraph.findAllAttackPaths();
        this.changePropagationDueToCredential.getAttackpaths().addAll(toAttackPaths(board, allAttackPathsSurface));
        
        // Clear caches
        CachePDP.instance().clearCache();
        //TODO remove: CacheVulnerability.instance().reset();
    }
    
    //TODO move toAttackPaths method to extra AttackPathConverter class
    /**
     * TODO method for testing the {@link AttackPathSurface} to {@link AttackPath} conversion.
     * 
     * @param allAttackPathsSurface - list of {@link AttackPathSurface} instances representing all found paths
     * @return list of {@link AttackPath} instances
     */
    public List<AttackPath> toAttackPaths(final List<AttackPathSurface> allAttackPathsSurface, 
            final BlackboardWrapper board) {
        return new ArrayList<>(toAttackPaths(board, allAttackPathsSurface));
    }

    private Collection<AttackPath> toAttackPaths(final BlackboardWrapper board,
            final List<AttackPathSurface> allAttackPathsSurface) {
        final List<AttackPath> allPaths = new ArrayList<>();
        
        for (final var pathSurface : allAttackPathsSurface) {
            final AttackPath path = AttackerFactory.eINSTANCE.createAttackPath();
            path.setCriticalElement(findCorrectSystemIntegration(board, this.crtitcalEntity, null).getPcmelement());
            
            path.getCredentialsInitiallyNecessary(); //TODO implement, adapt toAttackPath
            path.getVulnerabilitesUsed(); //TODO implement, adapt toAttackPath
            
            final var attackPathPath = toAttackPath(board, pathSurface);
            if (!attackPathPath.isEmpty()) {
                path.getPath().addAll(attackPathPath);
                allPaths.add(path);
            }
        }
        
        return allPaths;
    }
    
    private Collection<SystemIntegration> toAttackPath(BlackboardWrapper board,
            AttackPathSurface pathSurface) {
        final List<SystemIntegration> path = new ArrayList<>();
        
        for (final var edge : pathSurface) {
            final var nodes = edge.getNodes();
            // the edges in the attack path are reversed, 
            // so that the attacked is the target and the attacker the source
            final var attacked = nodes.target();
            final var attacker = nodes.source();

            if (!attacker.isCompromised()) {
                 // add default system integration (start of attack)
                final var sysInteg = generateDefaultSystemIntegration(attacker.getContainedElement());
                path.add(sysInteg);
            }
            
            final var edgeContent = edge.getContent();
            final var iter = edgeContent.getContainedSetVIterator(); //TODO also for C
            while (iter.hasNext()) {
                final var set = iter.next();
                for (final var cause : set) {
                    final var causeId = cause.getCauseId();
                    final var sysInteg = 
                            findCorrectSystemIntegration(board, attacked.getContainedElement(), causeId);
                    path.add(sysInteg); //TODO != null maybe
                }
            }
        }
        
        return path;
    }

    private static Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return PCMElementType.typeOf(entity).getElementIdEqualityPredicate(entity);
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

    private void createInitialStructure(BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getSurfaceattackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps().clear();

        for (final var attacker : attackers) { //TODO at the moment only one attacker allowed
            final var localAttacker = attacker.getAffectedElement();
            final var criticalPCMElement = localAttacker.getCriticalElement();
            this.crtitcalEntity = PCMElementType.typeOf(criticalPCMElement).getEntity(criticalPCMElement);

            final var listCredentialChanges = localAttacker.getAttacker().getCredentials()
                    .stream()
                    .map(context -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                change.setAffectedElement(context);
                return change;
            }).collect(Collectors.toList());

            this.changePropagationDueToCredential.getContextchange().addAll(listCredentialChanges);

            // convert affectedResources to changes
            final var affectedRessourcesList = localAttacker.getAttacker().
                    getCompromisedResources().stream().map(resource -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                change.setAffectedElement(resource);
                return change;
            }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedresource().addAll(affectedRessourcesList);
            
            //TODO add all possible attacks to the attack container and the attacker
            
            // convert affectedLinkingResources to changes
            final var affectedLinkingList = localAttacker.getAttacker().getCompromisedLinkingResources().stream()
                    .map(linkingResource -> {
                        final var change = KAMP4attackModificationmarksFactory.eINSTANCE
                                .createCompromisedLinkingResource();
                        change.setAffectedElement(linkingResource);
                        return change;
                    }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedlinkingresource().addAll(affectedLinkingList);

        }
        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changePropagationDueToCredential);
		
	}
	
    /**
     * Calculates the propagation starting from {@link AssemblyContext}s. 
     * The analyses start from the critical element and try to calculate back possible attack paths to it. <br/>
     * TODO: consider credentials and propagation to other model elements except assembly contexts 
     * 
     * @param board - the model storage
     */
    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        //TODO complete implementation
        
		final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationVulnerability(board, this.changePropagationDueToCredential, this.attackGraph));
        //list.add(new AssemblyContextPropagationContext(board));
        for (final var analysis : list) { //TODO adapt
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToAssemblyContextPropagation);
            /*TODO callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToAssemblyContextPropagation); 
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToGlobalAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToLocalResourcePropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToRemoteResourcePropagation);*/
            //TODO add others
        }
    }
    
    private void callMethodAfterResettingVisitations(final Runnable runnable) {
        this.attackGraph.resetVisitations();
        runnable.run();
    }

    private void calculateAndMarkResourcePropagation(final BlackboardWrapper board) {
        // TODO complete implementation
        
        final var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationVulnerability(board, this.changePropagationDueToCredential, this.attackGraph));
        //list.add(new ResourceContainerPropagationContext(board, this.changePropagationDueToCredential, this.attackDAG));
        for (final var analysis : list) { //TODO adapt
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToResourcePropagation);
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToLocalAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToRemoteAssemblyContextPropagation);
            //TODO add others
        }
    }

}
