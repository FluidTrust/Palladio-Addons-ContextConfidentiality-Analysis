package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil.EqualityHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextHandler extends AttackHandler {

	protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	public void attackAssemblyContext(final List<AssemblyContextDetail> components, final CredentialChange change,
			final EObject source) {

		for (AssemblyContextDetail component : components) {
			final var compromisedComponent = component.getAssemblyList().stream()
					.map(e -> attackComponent(e, change, source)).flatMap(Optional::stream)
					.collect(Collectors.toList());
			final var newCompromisedComponent = filterExsitingComponent(compromisedComponent, change);
			if (!newCompromisedComponent.isEmpty()) {
				handleDataExtraction(newCompromisedComponent);
				change.setChanged(true);
				// TODO: Die Zuteilung muss wieder auf die korrekten Kompoenten erfolgen
				// Aktuelle Konvention: Die übergeordnete Komponente (Index 0) bekommt wie
				// bisher die neuen kompromittierten Komponenten
				change.getCompromisedassembly().get(0).getAffectedElements().addAll(newCompromisedComponent);
				CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
						change);
			}
		}
	}

	private void handleDataExtraction(final Collection<CompromisedAssembly> components) {

		Collection<AssemblyContext> filteredComponents = components.stream()
				.map(CompromisedAssembly::getAffectedElement).collect(Collectors.toList());

		filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

		final var dataList = filteredComponents.stream().distinct()
				.flatMap(component -> DataHandler.getData(component).stream()).collect(Collectors.toList());

		getDataHandler().addData(dataList);
	}

	protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
			EObject source);

	private Collection<CompromisedAssembly> filterExsitingComponent(final Collection<CompromisedAssembly> components,
			final CredentialChange change) {
		return components.stream().filter(component -> !containsComponent(component, change))
				.collect(Collectors.toList());

	}

	private boolean containsComponent(final CompromisedAssembly component, final CredentialChange change) {
		return change.getCompromisedassembly().stream()
				.anyMatch(referenceComponent -> equalsForAny(referenceComponent.getAffectedElements(),
						component.getAffectedElement()));
	}

	private static boolean equalsForAny(List<CompromisedAssembly> assemblyList, AssemblyContext assembly) {
		EqualityHelper equalityHelper = new EqualityHelper();
		for (CompromisedAssembly compAssembly : assemblyList) {
			if (equalityHelper.equals(compAssembly, assembly)) {
				return true;
			}
		}
		return false;
	}

}
