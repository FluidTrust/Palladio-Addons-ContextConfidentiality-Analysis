package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.LinkedList;
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

import com.google.common.collect.Iterables;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.mitigation.MitigationHelper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * this class provides all the necessary methods for attacking AssemblyContexts
 * 
 * @author Maximilian Walter
 * @author Patrick Spiesberger
 *
 */
public abstract class AssemblyContextHandler extends AttackHandler {

	protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	/**
	 * This method manages the vulnerability of a List of AssemblyContextDetails
	 * 
	 * @param components : potentially vulnerable AssemblyContextDetails
	 * @param attacker   : necessary for the skills of an attacker
	 */
	public void attackAssemblyContext(final Collection<AssemblyContextDetail> components, final CredentialChange change,
			final EObject source, Attacker attacker) {

		List<CompromisedAssembly> compromisedComponents = new LinkedList<>();

		for (AssemblyContextDetail detail : components) {

			MitigationHelper mitigationHelper = new MitigationHelper();
			if (mitigationHelper.isCrackable(getMitigations(), Iterables.getLast(detail.getCompromisedComponents()),
					getAttacks(), change) && !lastElementDelegatesToMainComponent(detail)) {

				Optional<CompromisedAssembly> componentDetail = attackComponent(detail, change, source, attacker);
				if (componentDetail.isPresent()) {
					compromisedComponents.add(componentDetail.get());
				}
				final var newCompromisedComponent = filterExsitingComponent(compromisedComponents, change);
				if (!newCompromisedComponent.isEmpty()) {
					handleDataExtraction(newCompromisedComponent, change, attacker);
					change.setChanged(true);

					for (CompromisedAssembly component : newCompromisedComponent) {

						change.getCompromisedassembly().add(component);
					}

					CollectionHelper.addService(newCompromisedComponent,
							getModelStorage().getVulnerabilitySpecification(), change);
				}
			}
		}
	}

	private void handleDataExtraction(final Collection<CompromisedAssembly> components, CredentialChange change,
			Attacker attacker) {
		// puts all data from a set of components into a list of the DataHandler
		Collection<AssemblyContextDetail> filteredComponents = components.stream()
				.map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

		filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

		MitigationHelper mitigationHelper = new MitigationHelper();

		var dataList = filteredComponents.stream().map(e -> Iterables.getLast(e.getCompromisedComponents())).distinct()
				.flatMap(component -> DataHandler.getData(component, change).stream())
				.filter(data -> mitigationHelper.isCrackable(getMitigations(), data, attacker.getAttacks(), change))
				.collect(Collectors.toList());

		getDataHandler().addData(dataList);
	}

	/**
	 * Checks an AssemblyContextDetail for all of its vulnerabilities. It returns if
	 * one of the subcomponents or the main component itself is vulnerable
	 * 
	 * @return : vulnerable component if present
	 */
	protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContextDetail component,
			CredentialChange change, EObject source, Attacker attacker);

	private Collection<CompromisedAssembly> filterExsitingComponent(final Collection<CompromisedAssembly> components,
			final CredentialChange change) {
		return components.stream().filter(component -> !containsComponent(component, change))
				.collect(Collectors.toList());

	}

	private boolean containsComponent(final CompromisedAssembly component, final CredentialChange change) {
		return change.getCompromisedassembly().stream()
				.anyMatch(referenceComponent -> EcoreUtil.equals(
						referenceComponent.getAffectedElement().getCompromisedComponents(),
						component.getAffectedElement().getCompromisedComponents()));
	}

	/**
	 * By adding the CompositeComponents it can happen that subcomponents delegate
	 * to their main component. This would lead to erroneous output. Accordingly,
	 * the connection between subcomponent -> main component should not be added,
	 * because the main component is already at the top of the list by specification
	 * 
	 * @param detail : Component to be checked for this cycle
	 * @return : Is the last component in the list (if size > 1) the main component?
	 */
	private boolean lastElementDelegatesToMainComponent(AssemblyContextDetail detail) {
		if (detail.getCompromisedComponents().size() > 1) {
			return EcoreUtil.equals(detail.getCompromisedComponents().get(0),
					Iterables.getLast(detail.getCompromisedComponents()));
		} else {
			return false;
		}
	}
}
