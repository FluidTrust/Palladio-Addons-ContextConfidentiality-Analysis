package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;

import com.google.common.collect.Iterables;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.mitigation.MitigationHelper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class handles the attack on services
 * 
 * @author Maximilian Walter
 * @author patrick
 *
 */
public abstract class MethodHandler extends AttackHandler {

	public MethodHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	public void attackService(final Collection<ServiceRestriction> services, final CredentialChange change,
			final EObject source, Attacker attacker) {
		MitigationHelper mitigationHelper = new MitigationHelper();
		final var compromisedComponent = services.stream().map(e -> attackComponent(e, change, source, attacker))
				.filter(e -> e.isPresent())
				.filter(e -> mitigationHelper.isCrackable(getMitigations(),
						Iterables.getLast(e.get().getAffectedElement().getCompromisedComponents()), getAttacks(),
						change))
				.flatMap(Optional::stream).collect(Collectors.toList());
		final Collection<CompromisedAssembly> newCompromisedComponent = filterExsiting(compromisedComponent, change);
		if (!newCompromisedComponent.isEmpty()) {
			handleDataExtraction(newCompromisedComponent, change, attacker);
			change.setChanged(true);
			change.getCompromisedassembly().addAll(newCompromisedComponent);
			CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
					change);
		}
	}

	/**
	 * This method examines a list of compromised components for their data
	 * 
	 * @param components : List of compromised components
	 * @param attacker   : required for attacker skills
	 */
	private void handleDataExtraction(final Collection<CompromisedAssembly> components, CredentialChange change,
			Attacker attacker) {

		Collection<AssemblyContextDetail> filteredComponents = components.stream()
				.map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

		filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

		// considers the case as to whether encryption is possible
		MitigationHelper mitigationHelper = new MitigationHelper();

		var dataList = filteredComponents.stream().map(e -> Iterables.getLast(e.getCompromisedComponents())).distinct()
				.filter(component -> mitigationHelper.isCrackable(getMitigations(), component, getAttacks(), change))
				.flatMap(component -> DataHandler.getData(component, change).stream())
				.filter(data -> mitigationHelper.isCrackable(getMitigations(), data, attacker.getAttacks(), change))
				.collect(Collectors.toList());

		getDataHandler().addData(dataList);
	}

	protected abstract Optional<CompromisedAssembly> attackComponent(ServiceRestriction component,
			CredentialChange change, EObject source, Attacker attacker);

	/*
	 * filters out compromised assemblies already present in the changes
	 */
	private Collection<CompromisedAssembly> filterExsiting(final Collection<CompromisedAssembly> components,
			final CredentialChange change) {
		return components.stream().filter(component -> !contains(component, change)).collect(Collectors.toList());

	}

	private boolean contains(final CompromisedAssembly component, final CredentialChange change) {
		return change.getCompromisedassembly().stream()
				.anyMatch(referenceComponent -> EcoreUtil.equals(
						referenceComponent.getAffectedElement().getCompromisedComponents(),
						component.getAffectedElement().getCompromisedComponents()));
	}

	protected Vulnerability checkVulnerability(final ServiceRestriction entity, final CredentialChange change,
			final List<UsageSpecification> credentials, final List<Attack> attacks,
			final List<Vulnerability> vulnerabilityList, final AttackVector attackVector, Attacker attacker) {
		final var result = this.queryAccessForEntity(entity.getAssemblycontext(), credentials, entity.getSignature());
		return this.checkVulnerability(change, attacks, vulnerabilityList, attackVector, result, attacker);
	}

}
