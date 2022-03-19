package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CompromisedElementHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Mitigation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.ConfidentialityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.AttackVectorIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.Signature;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.CacheVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.mitigation.MitigationHelper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Generic class for handling attacks on system entities. Provides useful helper
 * methods for concrete subclasses
 *
 * @author majuwa
 * @author Patrick Spiesberger
 *
 */
public abstract class AttackHandler {
	private final BlackboardWrapper modelStorage;
	private final DataHandlerAttacker dataHandler;

	public AttackHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		Objects.requireNonNull(modelStorage);
		Objects.requireNonNull(dataHandler);

		this.modelStorage = modelStorage;
		this.dataHandler = dataHandler;

	}

	protected BlackboardWrapper getModelStorage() {
		return this.modelStorage;
	}

	protected DataHandlerAttacker getDataHandler() {
		return this.dataHandler;
	}

	protected final List<UsageSpecification> getCredentials(final CredentialChange changes) {
		return changes.getContextchange().stream().map(ContextChange::getAffectedElement).collect(Collectors.toList());
	}

	// TODO: Think about better location
	protected List<Attack> getAttacks() {
		final var listAttackers = this.modelStorage.getModificationMarkRepository().getSeedModifications()
				.getAttackcomponent();
		return listAttackers.stream().flatMap(e -> e.getAffectedElement().getAttacks().stream())
				.collect(Collectors.toList());
	}

	protected List<EObject> createSource(final EObject sourceItem,
			final List<? extends UsageSpecification> contextSet) {
		final List<EObject> list = new ArrayList<>();
		list.add(sourceItem);
		list.addAll(contextSet);
		return list;

	}

	/**
	 * Sends an access request to the policy decision point (PDP). <br \>
	 * <b>Important:</b> before the request the PDP must be initialised. This can be
	 * done with {@link Evaluate#initialize(String)}
	 *
	 * @param target      requested system entity
	 * @param credentials current credentials
	 * @return
	 *
	 * @see Evaluate#initialize(String)
	 */
	protected Optional<PDPResult> queryAccessForEntity(final Entity target,
			final List<? extends UsageSpecification> credentials, final Signature signature) {
		final var listComponent = new LinkedList<>(Arrays.asList(target));
		final var listSubject = new ArrayList<UsageSpecification>();
		final var listEnvironment = new ArrayList<UsageSpecification>();
		final var listResource = new ArrayList<UsageSpecification>();
		final var listXML = new ArrayList<UsageSpecification>();
		final var listOperation = new ArrayList<UsageSpecification>();

		if (signature == null) {
			PolicyHelper.createRequestAttributes(listComponent, credentials, listSubject, listEnvironment, listResource,
					listXML);
		} else {
			var result = CachePDP.instance().get(target, signature);
			if (result.isPresent()) {
				return result;
			}
			PolicyHelper.createRequestAttributes(signature, listComponent, credentials, listSubject, listEnvironment,
					listResource, listOperation, listXML);
		}

		final var result = getModelStorage().getEval().evaluate(listSubject, listEnvironment, listResource,
				listOperation, listXML);
		if (result.isPresent() && signature != null) {
			CachePDP.instance().insert(target, signature, result.get());
		}
		return result;
	}

	protected Optional<PDPResult> queryAccessForEntity(final Entity target,
			final List<? extends UsageSpecification> credentials) {
		var result = CachePDP.instance().get(target);
		if (result.isPresent()) {
			return result;
		}
		result = this.queryAccessForEntity(target, credentials, null);
		if (result.isPresent()) {
			CachePDP.instance().insert(target, result.get());
		}
		return result;
	}

	// TODO: Think about better location
	/**
	 * Checks whether the current vulnerabilities of a system entity (e.g.
	 * AssemblyContext, ResourceContainers ...) can be exploited by the capabilities
	 * of an attacker. It thereby considers the authorisation and the actual attack
	 * capabilities of the attacker
	 *
	 * @param entity            attacked system entity
	 * @param change            container with compromised entities
	 * @param credentials       credentials of the attacker
	 * @param attacks           attacks of the attacker
	 * @param vulnerabilityList Vulnerabilities of the system entity
	 * @param attackVector      attack vector of the attacker
	 * @return the vulnerability with the highest {@link ConfidentialityImpact} for
	 *         the system entity
	 */
	protected Vulnerability checkVulnerability(final Entity entity, final CredentialChange change,
			final List<UsageSpecification> credentials, final List<Attack> attacks,
			final List<Vulnerability> vulnerabilityList, final AttackVector attackVector, Attacker attacker) {
		if (CacheVulnerability.instance().checkedBefore(entity)) {
			return null;
		}
		Optional<PDPResult> result;
		var authenticatedNeeded = vulnerabilityList.stream().anyMatch(
				e -> Privileges.LOW.equals(e.getPrivileges()) || Privileges.SPECIAL.equals(e.getPrivileges()));
		if (authenticatedNeeded) {
			result = this.queryAccessForEntity(entity, credentials);
		} else {
			result = Optional.empty();
		}
		CacheVulnerability.instance().addEntity(entity);
		return this.checkVulnerability(change, attacks, vulnerabilityList, attackVector, result, attacker);
	}

	/**
	 * Checks whether the current vulnerabilities of a system entity (e.g.
	 * AssemblyContext, ResourceContainers ...) can be exploited by the capabilities
	 * of an attacker. It thereby considers the authorisation and the actual attack
	 * capabilities of the attacker
	 *
	 * @param change            container with compromised entities
	 * @param credentials       credentials of the attacker
	 * @param attacks           attacks of the attacker
	 * @param vulnerabilityList Vulnerabilities of the system entity
	 * @param attackVector      attack vector of the attacker
	 * @return the vulnerability with the highest {@link ConfidentialityImpact} for
	 *         the system entity
	 */
	protected Vulnerability checkVulnerability(final CredentialChange change, final List<Attack> attacks,
			final List<Vulnerability> vulnerabilityList, final AttackVector attackVector,
			final Optional<PDPResult> result, Attacker attacker) {
		var authenticated = false;
		if (result.isPresent()) {
			authenticated = DecisionType.PERMIT.equals(result.get().getDecision());
		}

		final var roleSpecification = VulnerabilityHelper.getRoles(getModelStorage().getVulnerabilitySpecification());

		// considers the case as to whether prevention is possible
		MitigationHelper mitigationHelper = new MitigationHelper();

		final var roles = roleSpecification.stream()
				.filter(e -> mitigationHelper.isCrackable(e.getPcmelement(), attacks, change))
				.filter(e -> CompromisedElementHelper.isHacked(e.getPcmelement(), change, attacks, attacker))
				.map(RoleSystemIntegration::getRole).collect(Collectors.toList());

		final var vulnerability = VulnerabilityHelper.checkAttack(authenticated, vulnerabilityList, attacks,
				attackVector, roles);
		return vulnerability;
	}

	/**
	 * For subcomponents, it may be possible for the attack vector to change to
	 * local. This property is returned in this method
	 * 
	 * @return true if subcomponent should be treated with a local attack vector
	 */
	public boolean changeAttackVector() {
		final var attackVectorSpecification = VulnerabilityHelper
				.getAttackVector(getModelStorage().getVulnerabilitySpecification());
		for (AttackVectorIntegration vector : attackVectorSpecification) {
			if (vector.isChangeAttackVectorToLocal()) {
				return true;
			}
		}
		return false;
	}

	public List<Mitigation> getMitigations() {
		return VulnerabilityHelper.getMitigations(getModelStorage().getVulnerabilitySpecification());
	}
}
