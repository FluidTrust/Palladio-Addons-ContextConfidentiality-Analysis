package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.DefaultSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.entity.Entity;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * Represents an attack path in an {@link AttackGraph}.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackPathSurface implements Iterable<AttackStatusEdge> {
    private final List<AttackStatusEdge> path;
    
    private final Set<CredentialSurface> initiallyNecessaryCredentials;
    
    /**
     * Creates a new empty {@link AttackPathSurface}.
     */
    public AttackPathSurface() {
        this.path = new LinkedList<>();
        this.initiallyNecessaryCredentials = new HashSet<>();
    }

    /**
     * Creates a new {@link AttackPathSurface} with a copy of the given list as an
     * initial path.
     * 
     * @param path - the path as a list of {@link AttackStatusEdge}
     * @param initiallyNecessaryCredentials - initially necessary credentials list
     */
    private AttackPathSurface(final List<AttackStatusEdge> path,
            final Set<CredentialSurface> initiallyNecessaryCredentials) {
        this.path = new LinkedList<>(path);
        this.initiallyNecessaryCredentials = new HashSet<>(initiallyNecessaryCredentials);
    }
    
    /**
     * Creates a new {@link AttackPathSurface} with a copy of the given list as an
     * initial path.
     * 
     * @param path - the path as a list of {@link AttackStatusEdge}
     */
    public AttackPathSurface(final List<AttackStatusEdge> path) {
        this.path = new LinkedList<>(path);
        this.initiallyNecessaryCredentials = new HashSet<>();
    }

    /**
     * Gets the {@link AttackStatusEdge} at the given index.
     * 
     * @param index - the given index
     * @return the edge at the index
     */
    public AttackStatusEdge get(final int index) {
        return this.path.get(index);
    }

    /**
     * 
     * @return the size of the path edge list, i.e. the count of edges
     */
    public int size() {
        return this.path.size();
    }

    /**
     * Adds the edge at the beginning of the path.
     * 
     * @param edge - the edge to be added
     */
    public void addFirst(final AttackStatusEdge edge) {
        this.path.add(0, edge);
    }

    /**
     * Adds the edge at the end of the path.
     * 
     * @param edge - the edge to be added
     */
    public void add(final AttackStatusEdge edge) {
        this.path.add(edge);
    }

    /**
     * 
     * @return whether the path is empty
     */
    public boolean isEmpty() {
        return this.path.isEmpty();
    }

    /**
     * 
     * @return a copy of the path (only the list is copied, not the edges)
     */
    public AttackPathSurface getCopy() {
        return new AttackPathSurface(this.path, this.initiallyNecessaryCredentials);
    }
    
    /**
     * 
     * @return a copy without self edges
     */
    public AttackPathSurface getCopyRemovedSelfEdges() {
        return new AttackPathSurface(this.path.stream()
                .filter(s -> !s.getNodes().target().equals(s.getNodes().source()))
                .collect(Collectors.toList()), 
                this.initiallyNecessaryCredentials);
    }

    @Override
    public Iterator<AttackStatusEdge> iterator() {
        return Collections.unmodifiableList(this.path).iterator();
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.path, this.initiallyNecessaryCredentials);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AttackPathSurface other = (AttackPathSurface) obj;
        return Objects.equals(this.path, other.path)
                && Objects.equals(this.initiallyNecessaryCredentials, other.initiallyNecessaryCredentials);
    }
    
    /**
     * 
     * @param other - the other path
     * @return whether the two paths consist of the same nodes in the same order
     */
    public boolean arePathNodesEquals(final AttackPathSurface other) {
        Objects.requireNonNull(other);
        if (size() == other.size()) {
            final int size = size();
            for (int i = 0; i < size; i++) {
                if (!path.get(i).getNodes().equals(other.path.get(i).getNodes())) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
    
    @Override
    public String toString() {
        return "AttackPathSurface [path=" + path + ", initiallyNecessaryCredentials=" + initiallyNecessaryCredentials
                + "]";
    }

    /**
     * Removes the first edge of the path.
     * 
     * @return this attack path after the removal
     */
    public AttackPathSurface removeFirst() {
        this.path.remove(0);
        return this;
    }

    /**
     * 
     * @return a stream of the edges
     */
    public Stream<AttackStatusEdge> stream() {
        return this.path.stream();
    }

    /**
     * Creates an output {@link AttackPath} from this path.
     * 
     * @param modelStorage - the model storage
     * @param criticalEntity - the critical entity
     * @param doCreateCauselessPaths - whether a path should be created without causes (for temporary paths)
     * @return an {@link AttackPath} representing this attack path
     */
    public AttackPath toAttackPath(BlackboardWrapper modelStorage, final Entity criticalEntity,
            final boolean doCreateCauselessPaths) {
        final List<SystemIntegration> localPath = new ArrayList<>();

        final int size = size();
        for (int i = 0; i < size; i++) {
            final var edge = this.get(i);
            final var nodes = edge.getNodes();
            // the edges in the attack path are reversed (w.respect to the attack graph direction),
            // so that the attacked is the target and the attacker the source
            final var attacked = nodes.target();
            final var attacker = nodes.source();

            if (doCreateCauselessPaths) {
                final var sysInteg = generateDefaultSystemIntegration(attacker.getContainedElement());
                localPath.add(sysInteg);
                if (i == this.size() - 1) {
                    final var attackedSysInteg = generateDefaultSystemIntegration(attacked.getContainedElement());
                    localPath.add(attackedSysInteg);
                }
            } else {
                if (i == 0) { // start of attack
                    iterateCauses(modelStorage, edge, localPath, attacker);
                }
                iterateCauses(modelStorage, edge, localPath, attacked);
            }
        }

        return createAttackPath(modelStorage, criticalEntity, localPath);
    }
    
    private void iterateCauses(BlackboardWrapper modelStorage,
            final AttackStatusEdge edge, 
            final List<SystemIntegration> localPath, 
            final AttackStatusNodeContent node) {
        final var edgeContent = edge.getContent();
        Iterable<Set<? extends CredentialsVulnearbilitiesSurface>> iterable = edgeContent::getContainedSetVIterator;
        boolean areCausesAdded = iterateCauses(modelStorage, localPath, node, iterable);
        iterable = edgeContent::getContainedSetCIterator;
        areCausesAdded |= iterateCauses(modelStorage, localPath, node, iterable);
        if (!areCausesAdded) { // add default integration
            final var sysInteg = generateDefaultSystemIntegration(node.getContainedElement());
            localPath.add(sysInteg);
        }
    }

    private boolean iterateCauses(final BlackboardWrapper modelStorage, 
            final List<SystemIntegration> localPath, 
            final AttackStatusNodeContent attacked,
            final Iterable<Set<? extends CredentialsVulnearbilitiesSurface>> iterable) {
        boolean ret = false;
        for (final var set : iterable) {
            for (final var cause : set) {
                final var causeId = cause.getCause();
                final var sysInteg = findCorrectSystemIntegration(modelStorage, attacked.getContainedElement(),
                        causeId);
                localPath.add(sysInteg);
                ret = true;
            }
        }
        return ret;
    }
    
    private AttackPath createAttackPath(BlackboardWrapper modelStorage, final Entity criticalEntity, 
            final List<SystemIntegration> localPath) {
        final var ret = AttackerFactory.eINSTANCE.createAttackPath();
        if (localPath.size() == 1) { // adding attack start, if not there
            final var startElement = localPath.get(0).getPcmelement();
            final var startEntity = PCMElementType.typeOf(startElement).getEntity(startElement);
            final var startOfAttack = generateDefaultSystemIntegration(startEntity);
            localPath.add(0, startOfAttack);
        }
        ret.getPath().addAll(localPath);
        ret.setCriticalElement(findCorrectSystemIntegration(modelStorage, criticalEntity, null).getPcmelement());

        ret.getCredentialsInitiallyNecessary().addAll(getCredentialsInitiallyNecessary(modelStorage));
        ret.getVulnerabilitesUsed().addAll(getUsedVulnerabilites(modelStorage));
        return ret;
    }

    /**
     * 
     * @param modelStorage - the model storage
     * @return the used vulnerabilities on this path
     */
    public Set<Vulnerability> getUsedVulnerabilites(final BlackboardWrapper modelStorage) {
        final Set<String> vulnerabilityCauseIds = stream().map(e -> e.getContent().getVulnerabilityCauseIds())
                .flatMap(Set::stream)
                .map(Identifier::getId).collect(Collectors.toSet());

        return modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
                .filter(s -> s.getIdOfContent() != null)
                .filter(s -> vulnerabilityCauseIds.contains(s.getIdOfContent().getId()))
                .filter(VulnerabilitySystemIntegration.class::isInstance)
                .map(VulnerabilitySystemIntegration.class::cast).map(VulnerabilitySystemIntegration::getVulnerability)
                .collect(Collectors.toSet());
    }
    
    private Collection<UsageSpecification> getCredentialsInitiallyNecessary(final BlackboardWrapper modelStorage) {
        return modelStorage.getSpecification().getUsagespecification()
                .stream()
                .filter(u -> this.initiallyNecessaryCredentials.contains(new CredentialSurface(u)))
                .collect(Collectors.toSet());
    }

    /**
     * 
     * @return this path after filling the credentials initially necessary from the nodes inside the path
     */
    public AttackPathSurface fillCredentialsInitiallyNecessary() {
        for (final var edge : this) {
            for (final var node : edge) {
                this.initiallyNecessaryCredentials.addAll(node.getAllNecessaryCauses());
            }
        }
        return this;
    }

    private static Predicate<SystemIntegration> getElementIdEqualityPredicate(final Entity entity) {
        return PCMElementType.typeOf(entity).getElementEqualityPredicate(entity);
    }

    private SystemIntegration findCorrectSystemIntegration(final BlackboardWrapper modelStorage, final Entity entity,
            Identifier cause) {
        final var container = modelStorage.getVulnerabilitySpecification().getVulnerabilities();
        if (container.stream().anyMatch(getElementIdEqualityPredicate(entity))) {
            final var sysIntegrations = container.stream().filter(getElementIdEqualityPredicate(entity))
                    .collect(Collectors.toList());
            final var sysIntegration = findCorrectSystemIntegration(sysIntegrations, cause);
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

    private SystemIntegration findCorrectSystemIntegration(final List<SystemIntegration> sysIntegrations, 
            final Identifier cause) {
        if (!sysIntegrations.isEmpty() && cause != null) {
            final SystemIntegration systemIntegrationById = 
                    findSystemIntegrationById(sysIntegrations, cause);
            // TODO later non-global communication
            if (systemIntegrationById != null) {
                return systemIntegrationById;
            }
            return copyDefaultOrFirst(sysIntegrations);
        }
        return null;
    }

    private static SystemIntegration findSystemIntegrationById(final List<SystemIntegration> sysIntegrations,
            final Identifier id) {
        if (id == null) {
            return copyDefaultOrFirst(sysIntegrations);
        }
        return copySystemIntegration(
                sysIntegrations.stream()
                    .filter(v -> v.getIdOfContent() != null)
                    .filter(v -> Objects.equals(id.getId(), v.getIdOfContent().getId())).findAny().orElse(null));
    }

    private static SystemIntegration copySystemIntegration(final SystemIntegration original) {
        if (original != null) {
            final SystemIntegration sysIntegration = original.getCopyExceptElement();
            sysIntegration.setPcmelement(PCMElementType.copy(original.getPcmelement()));
            return sysIntegration;
        }
        return original;
    }

    private static SystemIntegration copyDefaultOrFirst(final List<SystemIntegration> sysIntegrations) {
        return copySystemIntegration(sysIntegrations.stream().filter(DefaultSystemIntegration.class::isInstance).findAny()
                .orElse(sysIntegrations.get(0)));
    }

    /**
     * 
     * @return whether the path contains all the initially necessary credentials
     */
    public boolean containsInitiallyNecessaryCredentials() {
        final var credentialsNotUsed = new HashSet<>(this.initiallyNecessaryCredentials);
        for (final var edge : this.path) {
            credentialsNotUsed.removeIf(c -> 
                 edge.getContent().getCredentialCauseIds()
                     .stream()
                     .anyMatch(i -> i.getId().equals(c.getCauseId())));
        }
        return credentialsNotUsed.isEmpty();
    }

    public boolean isValid(final BlackboardWrapper modelStorage, final Entity criticalEntity) {
        final var attackPath = toAttackPath(modelStorage, criticalEntity, false);
        return (!attackPath.getCredentialsInitiallyNecessary().isEmpty()
                || doesUseVulnerabilityBeforeCredential(attackPath));
    }

    private static boolean doesUseVulnerabilityBeforeCredential(final AttackPath path) {
        final var vulnerabilitiesIds = path.getVulnerabilitesUsed().stream()
                .map(Identifier::getId).collect(Collectors.toSet());
        for (final var sysInteg : path.getPath()) {
            final String id = sysInteg.getIdOfContent() != null ? sysInteg.getIdOfContent().getId() : null;
            if (vulnerabilitiesIds.contains(id)) {
                return true;
            } else if (id != null) {
                return false;
            }
        }
        return false;
    }
}
