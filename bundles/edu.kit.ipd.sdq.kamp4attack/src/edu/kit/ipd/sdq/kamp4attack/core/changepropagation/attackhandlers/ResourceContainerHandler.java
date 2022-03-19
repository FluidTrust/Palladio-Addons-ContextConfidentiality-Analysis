package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.mitigation.MitigationHelper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * this class provides all the necessary methods for attacking ResourceContainers
 * 
 * @author Maximilian Walter
 * @author Patrick Spiesberger
 *
 */
public abstract class ResourceContainerHandler extends AttackHandler {

	public ResourceContainerHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	public void attackResourceContainer(final Collection<ResourceContainer> containers, final CredentialChange change,
			final EObject source, Attacker attacker) {
		final var compromisedResources = containers.stream()
				.map(e -> this.attackResourceContainer(e, change, source, attacker)).flatMap(Optional::stream)
				.distinct().collect(Collectors.toList());
		final var newCompromisedResources = filterExsiting(compromisedResources, change);
		if (!newCompromisedResources.isEmpty()) {
			handleDataExtraction(newCompromisedResources, change, attacker);
			change.setChanged(true);
			change.getCompromisedresource().addAll(newCompromisedResources);
		}
	}

	private void handleDataExtraction(final Collection<CompromisedResource> resources, CredentialChange change,
			Attacker attacker) {

		Collection<ResourceContainer> filteredComponents = resources.stream()
				.map(CompromisedResource::getAffectedElement).collect(Collectors.toList());

		filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);
		
		//considers the case as to whether encryption is possible
		MitigationHelper mitigationHelper = new MitigationHelper();
		
		final var dataList = filteredComponents.stream().flatMap(
				resource -> DataHandler.getData(resource, getModelStorage().getAllocation(), change).stream())
				.filter(data -> mitigationHelper.isCrackable(getMitigations(), data, attacker.getAttacks(), change)).collect(Collectors.toList());
		
		getDataHandler().addData(dataList);
	}

	protected abstract Optional<CompromisedResource> attackResourceContainer(ResourceContainer container,
			CredentialChange change, EObject source, Attacker attacker);

	private Collection<CompromisedResource> filterExsiting(final Collection<CompromisedResource> containers,
			final CredentialChange change) {
		return containers.stream().filter(container -> !contains(container, change)).collect(Collectors.toList());

	}

	private boolean contains(final CompromisedResource resource, final CredentialChange change) {
		return change.getCompromisedresource().stream().anyMatch(referenceContainer -> EcoreUtil
				.equals(referenceContainer.getAffectedElement(), resource.getAffectedElement()));
	}

}
