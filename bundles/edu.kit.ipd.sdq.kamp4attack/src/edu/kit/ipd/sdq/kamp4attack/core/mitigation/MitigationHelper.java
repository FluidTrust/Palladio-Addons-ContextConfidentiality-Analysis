package edu.kit.ipd.sdq.kamp4attack.core.mitigation;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Encryption;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Mitigation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MitigationSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.Prevention;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class is responsible for handling the crackability of encrypted data or
 * the prevention of an entire component
 * 
 * @author Patrick Spiesberger
 *
 */
public class MitigationHelper {

	public MitigationHelper() {

	}

	/**
	 * Checks whether a protection mechanism exists that can protect a PCMElement
	 * from attacker propagation
	 * 
	 * @param component : concrete component
	 * @param attacks   : list of attacks
	 * @param change    : changes of credentials
	 * @param attacker  : concrete attacker
	 * @return : True if the PCMElement has no protection mechanism or it can be
	 *         broken
	 */
	public boolean isCrackable(PCMElement component, final List<Attack> attacks, final CredentialChange change) {
		if (component.getMitigation() == null) {
			return true;
		}
		List<MitigationSpecification> mitigation = component.getMitigation().getMitigationspecification();
		if (mitigation.size() == 0) { // no mitigation defined
			return true;
		}
		for (Prevention prevention : filterPrevention(mitigation)) {
			var vulnerability = VulnerabilityHelper.checkAttack(false, prevention.getVulnerabilities(), attacks,
					AttackVector.LOCAL, null);
			if (vulnerability != null) {
				if (mitigationIsBreakable(prevention.getNecessaryCredentials(),
						getCredentials(change, vulnerability))) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Checks whether a protection mechanism exists that can protect a
	 * AssemblyContext from attacker propagation
	 * 
	 * @param mitigations : list of available mitigations
	 * @param component   : component to check
	 * @param attacks     : list of attacks
	 * @param change      : changes of credentials
	 * @param attacker    : concrete attacker
	 * @return : True if the AssemblyContext has no protection mechanism or it can
	 *         be broken
	 */
	public boolean isCrackable(final List<Mitigation> mitigations, AssemblyContext component,
			final List<Attack> attacks, final CredentialChange change) {
		if (component == null) {
			return true;
		}

		if (mitigations == null || mitigations.size() == 0) { // no mitigation defined
			return true;
		}

		List<MitigationSpecification> mitigationSpecifications = new LinkedList<>();

		for (Mitigation mitigation : mitigations) {
			if (mitigation.getPcmelement() != null && mitigation.getPcmelement().getAssemblycontext() != null) {
				if (EcoreUtil.equals(mitigation.getPcmelement().getAssemblycontext(), component)) {
					if (mitigation.getMitigationspecification() != null) {
						mitigationSpecifications.addAll(mitigation.getMitigationspecification());
					}
				}
			}
		}

		if (filterPrevention(mitigationSpecifications).size() == 0) {
			return true;
		}

		for (Prevention prevention : filterPrevention(mitigationSpecifications)) {
			var vulnerability = VulnerabilityHelper.checkAttack(false, prevention.getVulnerabilities(), attacks,
					AttackVector.LOCAL, null);
			if (mitigationIsBreakable(prevention.getNecessaryCredentials(), getCredentials(change, vulnerability))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks whether there are concrete mechanisms for protecting the data
	 * (encryption) and whether these can be broken
	 */
	public boolean isCrackable(final List<Mitigation> mitigations, final DatamodelAttacker data,
			final List<Attack> attacks, final CredentialChange change) {
		if (data == null) {
			return true;
		}
		if (mitigations == null || mitigations.size() == 0) { // no mitigation defined
			return true;
		}

		List<MitigationSpecification> mitigationSpecifications = new LinkedList<>();

		for (Mitigation mitigation : mitigations) {
			if (mitigation.getDatamodelcontainer() != null
					&& mitigation.getDatamodelcontainer().getDatamodelattacker() != null) {
				for (DatamodelAttacker attacker : mitigation.getDatamodelcontainer().getDatamodelattacker()) {
					if (checkEqualityOfData(data, attacker)) {
						if (mitigation.getMitigationspecification() != null) {
							mitigationSpecifications.addAll(mitigation.getMitigationspecification());
						}
					}
				}
			}
		}

		if (filterEncryption(mitigationSpecifications).size() == 0) {
			return true;
		}

		for (Encryption encryption : filterEncryption(mitigationSpecifications)) {
			var vulnerability = VulnerabilityHelper.checkAttack(false, encryption.getVulnerabilities(), attacks,
					AttackVector.LOCAL, null);
			if (mitigationIsBreakable(encryption.getNecessaryCredentials(), getCredentials(change, vulnerability))) {
				return true;
			}
		}
		return false;
	}

	private List<Prevention> filterPrevention(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(Prevention.class::isInstance).map(Prevention.class::cast)
				.collect(Collectors.toList());
	}

	private List<Encryption> filterEncryption(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(Encryption.class::isInstance).map(Encryption.class::cast)
				.collect(Collectors.toList());
	}

	private List<UsageSpecification> getCredentials(final CredentialChange changes, final Vulnerability vulnerability) {
		var permissions = changes.getContextchange().stream().map(ContextChange::getAffectedElement)
				.collect(Collectors.toList());

		if (vulnerability != null) {
			permissions.addAll(vulnerability.getGainedAttributes());
		}
		return permissions;
	}

	/**
	 * Checks whether the attacker has all the necessary attributes
	 * (UsageSpecification) to break the mitigation
	 * 
	 * @param requiredPermissions : permissions to break mitigation
	 * @param permissions         : actual permissions of the attacker
	 * @return true if mitigation is breakable (will therefore not be considered in
	 *         the further course)
	 */
	private boolean mitigationIsBreakable(List<UsageSpecification> requiredPermissions,
			List<UsageSpecification> permissions) {
		boolean contains = false;
		for (UsageSpecification specification : requiredPermissions) {
			for (UsageSpecification avaliableSpecification : permissions) {
				if (EcoreUtil.equals(specification, avaliableSpecification)) {
					contains = true;
				}
			}
			if (!contains) {
				return false;
			}
			contains = false;
		}
		return true;
	}

	/**
	 * checks whether the DatamodelAttacker a and b have the same content. This is
	 * necessary because the DatamodelAttacker is generated on the fly and is part
	 * of the output model. Therefore, these elements are specified in the
	 * mitigation and their content is checked
	 * 
	 * @param a : generated DatamodelAttacker
	 * @param b : specified DatamodelAttacker
	 * @return : are DatamodelAttacker equal?
	 */
	private boolean checkEqualityOfData(DatamodelAttacker a, DatamodelAttacker b) {
		try {
			if (a.getMethod() == null || b.getMethod() == null) {
				return a.getReferenceName().equals(b.getReferenceName());
			} else {
				return a.getMethod().getEntityName().equals(b.getMethod().getEntityName());
			}
		} catch (NullPointerException e) {
			return false;
		}
	}
}
