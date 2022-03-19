package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import com.google.common.base.Objects;
import com.google.common.collect.Iterables;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.contextSelection.ListOperations;
import edu.kit.ipd.sdq.kamp4attack.core.mitigation.MitigationHelper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class implements a concrete attack on an AssemblyContext
 * 
 * @author Maximilian Walter
 * @author Patrick Spiesberger
 *
 */
public class AssemblyContextContext extends AssemblyContextHandler {

	public AssemblyContextContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	@Override
	protected Optional<CompromisedAssembly> attackComponent(AssemblyContextDetail component, CredentialChange change,
			EObject source, Attacker attacker) {

		final var credentials = this.getCredentials(change);

		AssemblyContext lastComponent = Iterables.getLast(component.getCompromisedComponents());
		
		MitigationHelper mitigation = new MitigationHelper();
		if (!mitigation.isCrackable(getMitigations(), lastComponent, getAttacks(), change)) {
			return Optional.empty();
		}

		ListOperations listHelper = new ListOperations();

		// If only partial lists are returned, this is executed until all lists are
		// returned or a vulnerable component is found
		while (!listHelper.returnedAllElements()) {
			for (List<UsageSpecification> credential : listHelper.calculateLists(credentials, attacker)) {
				final var result = this.queryAccessForEntity(lastComponent, credential);

				if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
					final var sourceList = this.createSource(source, credential);

					final var compromised = HelperCreationCompromisedElements.createCompromisedAssembly(lastComponent,
							component, sourceList);

					return Optional.of(compromised);
				}
			}
		}
		return Optional.empty();
	}
}
