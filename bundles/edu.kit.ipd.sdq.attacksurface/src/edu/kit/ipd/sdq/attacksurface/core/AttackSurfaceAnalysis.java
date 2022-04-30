package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CVEVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEBasedVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.api.IAttackPropagationAnalysis;
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
public class AttackSurfaceAnalysis implements IAttackPropagationAnalysis {

    private CredentialChange changes;

    private Entity crtitcalEntity;

    private AttackGraph attackGraph;

    /**
     * Constructor, when {@link #runChangePropagationAnalysis(BlackboardWrapper)} is called.
     */
    public AttackSurfaceAnalysis() {
        this(false, null);
    }
    
    /**
     * Constructor for tests, initializes the initial structure.
     * 
     * @param doInitialize - if the initial structure should be already created
     * @param modelStorage - the model storage
     */
    public AttackSurfaceAnalysis(final boolean doInitialize, final BlackboardWrapper modelStorage) {
        if (doInitialize) {
            this.changes = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
            this.createInitialStructure(modelStorage);
        }
    }
    
    public AttackSurfaceAnalysis(AttackGraph attackGraph) {
        this.attackGraph = attackGraph;
    }

    /**
     * Runs the analysis.
     * 
     * @param modelStorage - the model storage
     */
    public void runChangePropagationAnalysis(final BlackboardWrapper modelStorage) {
        runPropagationWithoutAttackPathCreation(modelStorage);
        createAttackPaths(modelStorage);
        cleanup(modelStorage);
    }
    
    public CredentialChange runAnalysisTest(final BlackboardWrapper modelStorage) {
        runChangePropagationAnalysis(modelStorage);
        return this.changes;
    }
    
    private void initialize(final BlackboardWrapper modelStorage) {
        this.changes = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        createInitialStructure(modelStorage);
    }
    
    private void calculate(final BlackboardWrapper modelStorage) {
        do {
            this.changes.setChanged(false);
            this.attackGraph.resetVisitations();

            calculateAndMarkResourcePropagation(modelStorage);
            calculateAndMarkAssemblyPropagation(modelStorage);

            //TODO later implement calculateAndMarkLinkingPropagation(board);
        } while (this.changes.isChanged());
    }
    
    private void createAttackPaths(final BlackboardWrapper modelStorage) {
        this.attackGraph.resetVisitations();
        final var allAttackPathsSurface = this.attackGraph.findAllAttackPaths(modelStorage, this.changes);
        this.changes.getAttackpaths().addAll(toAttackPaths(modelStorage, allAttackPathsSurface));
    }
    
    /*
     * public for test
     */
    public CredentialChange runPropagationWithoutAttackPathCreation(final BlackboardWrapper modelStorage) {
        initialize(modelStorage);
        calculate(modelStorage);
        return this.changes;
    }
    
    /*
     * public for tests
     */
    public void cleanup(final BlackboardWrapper modelStorage) {
        removeReferencedAttacks(modelStorage);
    }

    /*
     * remove temporarily created referenced attacks
     */
    private void removeReferencedAttacks(final BlackboardWrapper modelStorage) {
        final var repository = modelStorage.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getSurfaceattackcomponent();
        final var attacker = attackers.get(0);
        final var localAttacker = attacker.getAffectedElement();
        localAttacker.getAttacker().getAttacks().clear();
    }

    /**
     * Method for testing the {@link AttackPathSurface} to {@link AttackPath}
     * conversion.
     * 
     * @param allAttackPathsSurface - list of {@link AttackPathSurface} instances
     *                              representing all found paths
     * @param modelStorage
     * @return list of {@link AttackPath} instances
     */
    public List<AttackPath> toAttackPaths(final List<AttackPathSurface> allAttackPathsSurface,
            final BlackboardWrapper modelStorage) {
        return new ArrayList<>(toAttackPaths(modelStorage, allAttackPathsSurface));
    }

    private Collection<AttackPath> toAttackPaths(final BlackboardWrapper modelStorage,
            final List<AttackPathSurface> allAttackPathsSurface) {
        final List<AttackPath> allPaths = new ArrayList<>();

        for (final var pathSurface : allAttackPathsSurface) {
            final var attackPathPath = pathSurface.toAttackPath(modelStorage, this.crtitcalEntity, false);
            if (!attackPathPath.getPath().isEmpty() && !isFiltered(modelStorage, attackPathPath)
                    && isLastElementCriticalElement(attackPathPath)
                    && !contains(allPaths, attackPathPath)) {
                allPaths.add(attackPathPath);
            }
        }

        return allPaths;
    }
    
    private boolean contains(final List<AttackPath> allPaths, final AttackPath newPath) {
        return allPaths.stream().anyMatch(p -> isPathEquals(p, newPath));
    }

    private boolean isPathEquals(AttackPath expected, AttackPath actual) {
        if (expected.getPath().size() != actual.getPath().size()) {
            return false;
        }
        final int size = expected.getPath().size();
        for (int i = 0; i < size; i++) {
            final var sysIntegActual = actual.getPath().get(i);
            final var actualEntity = PCMElementType.typeOf(sysIntegActual.getPcmelement())
                    .getEntity(sysIntegActual.getPcmelement());
            final var sysIntegExpected = expected.getPath().get(i);
            final boolean elementEquals = 
                    PCMElementType.typeOf(sysIntegExpected.getPcmelement())
                        .getElementEqualityPredicate(actualEntity).test(sysIntegExpected);
            if (!elementEquals) {
                return false;
            }
            final boolean idOfContentEquals = 
                    Objects.equals(sysIntegExpected.getIdOfContent(), sysIntegActual.getIdOfContent());
            if (!idOfContentEquals) {
                return false;
            }
        }
        return true;
    }

    private boolean isLastElementCriticalElement(final AttackPath attackPath) {
        final var path = attackPath.getPath();
        final var lastElement = path.get(path.size() - 1).getPcmelement();
        final var lastEntity = PCMElementType.typeOf(lastElement).getEntity(lastElement);
        return lastEntity.getId().equals(this.crtitcalEntity.getId());
    }

    private boolean isFiltered(final BlackboardWrapper board, final AttackPath path) {
        return AttackHandlingHelper.isFiltered(board, path, false);
    }

    private void createInitialStructure(BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var localAttacker = AttackHandlingHelper.getSurfaceAttacker(board);

        repository.getChangePropagationSteps().clear();

        final var criticalPCMElement = localAttacker.getCriticalElement();
        this.crtitcalEntity = PCMElementType.typeOf(criticalPCMElement).getEntity(criticalPCMElement);
        this.attackGraph = this.attackGraph != null ? this.attackGraph : new AttackGraph(this.crtitcalEntity);
        
        final var setCredentials = localAttacker.getAttacker().getCredentials().stream()
                .map(CredentialSurface::new).collect(Collectors.toSet());
        this.attackGraph.addCredentialsFromBeginningOn(setCredentials);
        convertAffectedElementsToChanges(localAttacker); 
        addAllPossibleAttacks(board, localAttacker);
        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changes);
    }
    
    private void convertAffectedElementsToChanges(final SurfaceAttacker localAttacker) {
        //TODO later add the resulting attack paths
        
        // convert affectedResources to changes
        final var affectedRessourcesList = localAttacker.getAttacker().getCompromisedResources().stream()
                .map(resource -> {
                    final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                    change.setAffectedElement(resource);
                    return change;
                }).collect(Collectors.toList());
        this.changes.getCompromisedresource().addAll(affectedRessourcesList);

        // convert affectedLinkingResources to changes
        final var affectedLinkingList = localAttacker.getAttacker().getCompromisedLinkingResources().stream()
                .map(linkingResource -> {
                    final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
                    change.setAffectedElement(linkingResource);
                    return change;
                }).collect(Collectors.toList());
        this.changes.getCompromisedlinkingresource().addAll(affectedLinkingList);
    }

    private void addAllPossibleAttacks(final BlackboardWrapper board, final SurfaceAttacker localAttacker) {
        var vulnerabilities = board.getVulnerabilitySpecification().getVulnerabilities().stream()
                .filter(VulnerabilitySystemIntegration.class::isInstance)
                .map(VulnerabilitySystemIntegration.class::cast).map(VulnerabilitySystemIntegration::getVulnerability)
                .collect(Collectors.toSet());
        final var attacks = CollectionHelper.removeDuplicates(vulnerabilities).stream().map(this::toAttack)
                .flatMap(Set::stream).filter(Objects::nonNull).collect(Collectors.toSet());
        localAttacker.getAttacker().getAttacks().addAll(attacks);
    }

    private Set<Attack> toAttack(final Vulnerability vulnerability) {
        if (vulnerability instanceof CVEVulnerability) {
            final Set<Attack> attacks = new HashSet<>();
            final var cveVuln = (CVEVulnerability) vulnerability;
            final var attack = AttackSpecificationFactory.eINSTANCE.createCVEAttack();
            attack.setCategory(cveVuln.getCveID());
            attacks.add(attack);
            return attacks;
        } else if (vulnerability instanceof CWEBasedVulnerability) {
            final Set<Attack> attacks = new HashSet<>();
            final var cweVuln = (CWEBasedVulnerability) vulnerability;
            for (final var id : cweVuln.getCweID()) {
                final var attack = AttackSpecificationFactory.eINSTANCE.createCWEAttack();
                attack.setCategory(id);
                attacks.add(attack);
            }
            return attacks;
        }
        throw new IllegalArgumentException("unknown vulnerability type");
    }

    /**
     * Calculates the propagation starting from {@link AssemblyContext}s. The
     * analyses start from the critical element and try to calculate back possible
     * attack paths to it.
     * 
     * @param modelStorage - the model storage
     */
    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper modelStorage) {
        final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationVulnerability(modelStorage, this.changes,
                this.attackGraph));
        list.add(new AssemblyContextPropagationContext(modelStorage, this.changes, this.attackGraph));
        for (final var analysis : list) {
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToGlobalAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToLocalResourcePropagation);
            callMethodAfterResettingVisitations(analysis::calculateAssemblyContextToRemoteResourcePropagation);
            // TODO later to linking
        }
    }

    private void callMethodAfterResettingVisitations(final Runnable runnable) {
        this.attackGraph.resetVisitations();
        runnable.run();
    }

    /**
     * Calculates the propagation starting from {@link ResourceContainer}s. The
     * analyses start from the critical element and try to calculate back possible
     * attack paths to it.
     * 
     * @param modelStorage - the model storage
     */
    private void calculateAndMarkResourcePropagation(final BlackboardWrapper modelStorage) {
        final var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationVulnerability(modelStorage, this.changes,
                this.attackGraph));
        list.add(new ResourceContainerPropagationContext(modelStorage, this.changes,
                this.attackGraph));
        for (final var analysis : list) {
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToResourcePropagation);
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToLocalAssemblyContextPropagation);
            callMethodAfterResettingVisitations(analysis::calculateResourceContainerToRemoteAssemblyContextPropagation);
            // TODO later to linking
        }
    }

    private void calculateAndMarkLinkingPropagation(BlackboardWrapper modelStorage) {
        // TODO later implement
    }
}
