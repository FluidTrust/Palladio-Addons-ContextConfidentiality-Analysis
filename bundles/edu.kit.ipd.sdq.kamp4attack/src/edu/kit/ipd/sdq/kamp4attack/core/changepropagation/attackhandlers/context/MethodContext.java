package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;

import com.google.common.base.Objects;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.MethodHandler;
import edu.kit.ipd.sdq.kamp4attack.core.contextSelection.ListOperations;
import edu.kit.ipd.sdq.kamp4attack.core.mitigation.MitigationHelper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class implements a concrete attack on an assembly context
 * 
 * @author Maximilian Walter
 * @author Patrick Spiesberger
 *
 */
public class MethodContext extends MethodHandler {

	public MethodContext(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	@Override
	protected Optional<CompromisedAssembly> attackComponent(ServiceRestriction service, CredentialChange change,
			EObject source, Attacker attacker) {
		final var credentials = getCredentials(change);

		var serviceModel = CollectionHelper.findOrCreateServiceRestriction(service,
				getModelStorage().getVulnerabilitySpecification(), change);

		MitigationHelper mitigation = new MitigationHelper();
		if (!mitigation.isCrackable(getMitigations(), serviceModel.getAssemblycontext(), getAttacks(), change)) {
			return Optional.empty();
		}

		ListOperations listHelper = new ListOperations();

		// If only partial lists are returned, this is executed until all lists are
		// returned or a vulnerable component is found
		while (!listHelper.returnedAllElements()) {
			for (List<UsageSpecification> credential : listHelper.calculateLists(credentials, attacker)) {
				final var result = this.queryAccessForEntity(serviceModel.getAssemblycontext(), credential,
						serviceModel.getSignature());

				if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
					final var sourceList = createSource(source, credential);

					final var compromised = HelperCreationCompromisedElements.createCompromisedService(serviceModel,
							sourceList);
					var serviceRestrictions = CollectionHelper.filterExistingService(List.of(compromised), change);
					if (!serviceRestrictions.isEmpty()) {
						change.getCompromisedservice().addAll(serviceRestrictions);
						change.setChanged(true);
						return Optional.empty();
					}

					// TODO think about parameter handling e.g. only access is granted but data of
					// parametes
					// is usally not compromised. Return value might
					// var data = DataHandler.getData(service.getService());
					// getDataHandler().addData(data);
				}
			}

		}
		return Optional.empty();
	}

}
