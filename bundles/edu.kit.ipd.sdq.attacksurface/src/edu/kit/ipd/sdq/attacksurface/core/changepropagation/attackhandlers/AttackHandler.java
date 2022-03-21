package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CompromisedElementHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.ConfidentialityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.CredentialSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.Signature;

import com.google.common.graph.EndpointPair;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.credentialquerying.CredentialQuerying;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.credentialquerying.SimpleCredentialQuerying;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdgeContent;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialsVulnearbilitiesSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

/**
 * Generic class for handling attacks on system entities. Provides useful helper methods for
 * concrete subclasses.
 *
 * @author majuwa
 * @author ugnwq
 */
public abstract class AttackHandler implements CredentialQuerying {
    private final BlackboardWrapper modelStorage;
    private final DataHandlerAttacker dataHandler;
    private final AttackGraph attackGraph;
    private final CredentialQuerying querying;

    public AttackHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        Objects.requireNonNull(modelStorage);
        Objects.requireNonNull(dataHandler);
        Objects.requireNonNull(attackGraph);

        this.modelStorage = modelStorage;
        this.dataHandler = dataHandler;
        this.attackGraph = attackGraph;
        this.querying = new SimpleCredentialQuerying(modelStorage);
    }

    @Override
    public BlackboardWrapper getModelStorage() {
        return this.modelStorage;
    }

    protected DataHandlerAttacker getDataHandler() {
        return this.dataHandler;
    }
    
    protected AttackGraph getAttackGraph() {
        return this.attackGraph;
    }
    
    /**
     * 
     * @param causingElements - the given causing elements
     * @return the set of IDs of causes for the given causing elements
     */
    protected abstract Set<Identifier> getCauses(EList<EObject> causingElements);
    
    /**
     * 
     * @return the mapper from the cause Identifier to a {@link CredentialsVulnearbilitiesSurface}
     */
    protected abstract Function<Identifier, CredentialsVulnearbilitiesSurface> getSurfaceMapper();

    /**
     * Selects the node to be compromised and compromises it afterwards with 
     * {@link AttackGraph#compromiseSelectedNode(Set, AttackStatusNodeContent)}. <br/>
     * The node remains selected.
     * 
     * @param causingElements - the causing elements list
     * @param compromisedNode - the node to be compromised
     * @param attackSource - the attack source
     */
    protected final void compromise(final EList<EObject> causingElements, 
            final AttackStatusNodeContent compromisedNode,
            final AttackStatusNodeContent attackSource) {
        final var causes = getCauses(causingElements)
                .stream()
                .map(getSurfaceMapper())
                .collect(Collectors.toSet());
        getAttackGraph().setSelectedNode(compromisedNode);
        getAttackGraph().compromiseSelectedNode(causes, attackSource);
    }
    
    /**
     * Gets the credentials from the attack graph.
     * 
     * @param source - the attack source node
     * @param target - the attacked node
     * @return the credentials usable at the moment
     */
    protected final List<UsageSpecification> getAllCredentials(
            final AttackStatusNodeContent source, 
            final AttackStatusNodeContent target) {
        final var edge = new AttackStatusEdge(new AttackStatusEdgeContent(), 
                EndpointPair.ordered(source, target));
        return this.attackGraph.getCredentials(edge).stream().map(this::findCredential).collect(Collectors.toList());
    }
    
    private UsageSpecification findCredential(final CredentialSurface credential) {
        return this.modelStorage.getSpecification().getUsagespecification().stream()
                    .filter(u -> u.getId().equals(credential.getCauseId())).findFirst().orElse(null);
    }
    
    /**
     * 
     * @param source - the attack source node
     * @param target - the attacked node
     * @return the credentials relevant for the attack
     */
    protected final List<UsageSpecification> getRelevantCredentials(
            final AttackStatusNodeContent source, 
            final AttackStatusNodeContent target) {
        final var idsOfRelevantUsageSpecifications = 
                this.modelStorage.getVulnerabilitySpecification().getVulnerabilities()
                    .stream()
                    .filter(s -> PCMElementType.typeOf(s.getPcmelement())
                            .getElementEqualityPredicate(target.getContainedElement()).test(s))
                    .filter(CredentialSystemIntegration.class::isInstance)
                    .map(SystemIntegration::getIdOfContent)
                    .collect(Collectors.toSet());
        return getAllCredentials(source, target)
                .stream()
                .filter(u -> idsOfRelevantUsageSpecifications.contains(u.getId()))
                .collect(Collectors.toList());
    }

    protected List<Attack> getAttacks() {
        return AttackHandlingHelper.getAttacks(this.modelStorage);
    }

    protected List<EObject> createSource(final EObject sourceItem,
            final List<? extends UsageSpecification> contextSet) {
        final List<EObject> list = new ArrayList<>();
        list.add(sourceItem);
        list.addAll(contextSet);
        return list;

    }
    
    @Override
    public Optional<PDPResult> queryAccessForEntity(final Entity target,
            final List<? extends UsageSpecification> credentials, final Signature signature) {
        return this.querying.queryAccessForEntity(target, credentials, signature);
    }

    // TODO: Think about better location
    /**
     * Checks whether the current vulnerabilities of a system entity (e.g. AssemblyContext,
     * ResourceContainers ...) can be exploited by the capabilities of an attacker. It thereby
     * considers the authorisation and the actual attack capabilities of the attacker
     *
     * @param entity
     *            attacked system entity
     * @param change
     *            container with compromised entities
     * @param credentials
     *            credentials of the attacker
     * @param attacks
     *            attacks of the attacker
     * @param vulnerabilityList
     *            Vulnerabilities of the system entity
     * @param attackVector
     *            attack vector of the attacker
     * @return the vulnerability with the highest {@link ConfidentialityImpact} for the system
     *         entity
     */
    protected Vulnerability checkVulnerability(final Entity entity, final CredentialChange change,
            final List<UsageSpecification> credentials, final List<Attack> attacks,
            final List<Vulnerability> vulnerabilityList, final AttackVector attackVector) {
        Optional<PDPResult> result;
        var authenticatedNeeded = vulnerabilityList.stream().anyMatch(
                e -> Privileges.LOW.equals(e.getPrivileges()) || Privileges.SPECIAL.equals(e.getPrivileges()));
        if (authenticatedNeeded) {
            result = this.queryAccessForEntity(entity, credentials);
        } else {
            result = Optional.empty();
        }

        return this.checkVulnerability(change, attacks, vulnerabilityList, attackVector, result);
    }

    /**
     * Checks whether the current vulnerabilities of a system entity (e.g. AssemblyContext,
     * ResourceContainers ...) can be exploited by the capabilities of an attacker. It thereby
     * considers the authorisation and the actual attack capabilities of the attacker
     *
     * @param change
     *            container with compromised entities
     * @param credentials
     *            credentials of the attacker
     * @param attacks
     *            attacks of the attacker
     * @param vulnerabilityList
     *            Vulnerabilities of the system entity
     * @param attackVector
     *            attack vector of the attacker
     * @return the vulnerability with the highest {@link ConfidentialityImpact} for the system
     *         entity
     */
    protected Vulnerability checkVulnerability(final CredentialChange change, final List<Attack> attacks,
            final List<Vulnerability> vulnerabilityList, final AttackVector attackVector,
            final Optional<PDPResult> result) {
        var authenticated = false;
        if (result.isPresent()) {
            authenticated = DecisionType.PERMIT.equals(result.get().getDecision());
        }

        final var roleSpecification = VulnerabilityHelper
                .getRoles(getModelStorage().getVulnerabilitySpecification());

        final var roles = roleSpecification.stream()
                .filter(e -> CompromisedElementHelper.isHacked(e.getPcmelement(), change))
                .map(RoleSystemIntegration::getRole).collect(Collectors.toList());

        final var vulnerability = VulnerabilityHelper.checkAttack(authenticated, vulnerabilityList, attacks,
                attackVector, roles);
        return vulnerability;
    }
    
    /**
     * Filters the already existing edges.
     * 
     * @param compromisedEntities - the comporomised entities
     * @param source - the attack source
     * @param clazz - the class of the ModifyEntity
     * @return the edges that do not yet exist
     */
    protected Collection<ModifyEntity<?>> filterExistingEdges(
            final List<? extends ModifyEntity<?>> compromisedEntities, final Entity source,
            final Class<? extends ModifyEntity<?>> clazz) {
        final boolean areThereUncompromisedElementsInGraph = 
                !areAllCompromisedComponentsCompromisedInGraph(compromisedEntities);
        return compromisedEntities
                .stream()
                .filter(c -> areElementsNotFiltered(c, areThereUncompromisedElementsInGraph, source))
                .collect(Collectors.toList());
    }
    
    private boolean areElementsNotFiltered(final ModifyEntity<? extends Entity> compromisedEntity,
            final boolean areThereUncompromisedElementsInGraph, final Entity source) {
        final var attackerNode = new AttackStatusNodeContent(source);
        final var attackedNode = new AttackStatusNodeContent(compromisedEntity.getAffectedElement());
        final var compromisationCauses = getCausesOfCompromisation(compromisedEntity);
        final boolean isAttackToContainedAssembliesInResource = 
                compromisationCauses.isEmpty() && areThereUncompromisedElementsInGraph;
        return isAttackToContainedAssembliesInResource
                || !contains(getAttackGraph().getEdge(attackedNode, 
                        attackerNode), compromisationCauses);
    }

    private boolean areAllCompromisedComponentsCompromisedInGraph(
            List<? extends ModifyEntity<? extends Entity>> compromisedComponents) {
        final var compromisedComponentsInGraphIds = getAttackGraph()
                .getCompromisedNodes()
                .stream()
                .map(n -> n.getContainedElement().getId())
                .collect(Collectors.toSet());
        final var compromisedComponentsIds = compromisedComponents
                .stream()
                .map(ModifyEntity::getAffectedElement)
                .map(Identifier::getId)
                .collect(Collectors.toSet());
        return compromisedComponentsInGraphIds.containsAll(compromisedComponentsIds);
    }

    /**
     * 
     * @param edgeContent - the edge content
     * @param causesOfCompromisation - the causes of compromisation
     * @return whether the edge contains all the causes of compromisation
     */
    protected boolean contains(final AttackStatusEdgeContent edgeContent, final Set<Identifier> causesOfCompromisation) {
        return edgeContent != null && edgeContent.getCauses().containsAll(causesOfCompromisation);
    }

    /**
     * 
     * @param attacked - the attacked modify entity
     * @return the set of cause IDs of the causes of the attacked entity
     */
    protected final Set<Identifier> getCausesOfCompromisation(final ModifyEntity<?> attacked) {
        return getCauses(attacked.getCausingElements());
    }
}
