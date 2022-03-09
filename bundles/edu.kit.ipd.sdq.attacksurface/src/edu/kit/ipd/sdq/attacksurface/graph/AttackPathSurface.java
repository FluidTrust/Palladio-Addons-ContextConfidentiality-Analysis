package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Arrays;
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

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;

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
        return new AttackPathSurface(new ArrayList<>(this.path));
    }

    @Override
    public Iterator<AttackStatusEdge> iterator() {
        return Collections.unmodifiableList(this.path).iterator();
    }

    @Override
    public int hashCode() {
        return Objects.hash(path);
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
        return Objects.equals(path, other.path);
    }

    @Override
    public String toString() {
        return "AttackPathSurface [path=" + path + "]";
    }

    public AttackPathSurface remove(int index) {
        this.path.remove(index);
        return this;
    }

    public Stream<AttackStatusEdge> stream() {
        return this.path.stream();
    }

    public AttackPath toAttackPath(BlackboardWrapper board, final Entity criticalEntity,
            final boolean doCreateCauselessPaths) {
        final List<SystemIntegration> localPath = new ArrayList<>();

        for (int i = 0; i < this.size(); i++) {
            final var edge = this.get(i);
            final var nodes = edge.getNodes();
            // the edges in the attack path are reversed,
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
                if (!attacker.isCompromised()) {
                    // add default system integration (start of attack)
                    final var sysInteg = generateDefaultSystemIntegration(attacker.getContainedElement());
                    localPath.add(sysInteg);
                }

                final var edgeContent = edge.getContent();
                Iterable<Set<CVSurface>> iterable = edgeContent::getContainedSetVIterator;
                boolean areCausesAdded = iterateCauses(board, localPath, attacked, iterable);
                iterable = edgeContent::getContainedSetCIterator;
                areCausesAdded |= iterateCauses(board, localPath, attacked, iterable);
                if (!areCausesAdded) { // add default integration
                    final var attackedSysInteg = generateDefaultSystemIntegration(attacked.getContainedElement());
                    localPath.add(attackedSysInteg);
                }
            }
        }

        final var ret = AttackerFactory.eINSTANCE.createAttackPath();
        ret.getPath().addAll(localPath);
        ret.setCriticalElement(findCorrectSystemIntegration(board, criticalEntity, null).getPcmelement());

        ret.getCredentialsInitiallyNecessary().addAll(getCredentialsInitiallyNecessary(board));
        ret.getVulnerabilitesUsed().addAll(getUsedVulnerabilites(board));
        return ret;
    }


    private boolean iterateCauses(final BlackboardWrapper board, 
            final List<SystemIntegration> localPath, 
            final AttackStatusNodeContent attacked,
            final Iterable<Set<CVSurface>> iterable) {
        boolean ret = false;
        for (final var set : iterable) {
            for (final var cause : set) {
                final var causeId = cause.getCauseId();
                final var sysInteg = findCorrectSystemIntegration(board, attacked.getContainedElement(),
                        causeId);
                localPath.add(sysInteg);
                ret = true;
            }
        }
        return ret;
    }

    public Set<Vulnerability> getUsedVulnerabilites(final BlackboardWrapper board) {
        final Set<String> vulnerabilityCauseIds = stream().map(e -> e.getContent().getVulnerabilityCauseIds())
                .flatMap(Set::stream).collect(Collectors.toSet());

        return board.getVulnerabilitySpecification().getVulnerabilities().stream()
                .filter(s -> vulnerabilityCauseIds.contains(s.getIdOfContent()))
                .filter(VulnerabilitySystemIntegration.class::isInstance)
                .map(VulnerabilitySystemIntegration.class::cast).map(VulnerabilitySystemIntegration::getVulnerability)
                .collect(Collectors.toSet());
    }
    
    private Collection<UsageSpecification> getCredentialsInitiallyNecessary(final BlackboardWrapper board) {
        return board.getSpecification().getUsagespecification()
                .stream()
                .filter(u -> this.initiallyNecessaryCredentials.contains(new CredentialSurface(u.getId())))
                .collect(Collectors.toSet());
    }

    public AttackPathSurface fillCredentialsInitiallyNecessary() {
        for (final var edge : this) {
            for (final var node : edge) {
                node.moveAllNecessaryCausesToSet(this.initiallyNecessaryCredentials);
            }
        }
        return this;
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
}
