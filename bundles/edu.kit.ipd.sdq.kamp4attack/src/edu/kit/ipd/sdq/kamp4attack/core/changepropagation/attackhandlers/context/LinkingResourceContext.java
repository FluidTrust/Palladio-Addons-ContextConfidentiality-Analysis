package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import com.google.common.base.Objects;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.contextSelection.ListOperations;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class implements a concrete attack on a LinkingResource
 * 
 * @author Maximilian Walter
 * @author Patrick Spiesberger
 *
 */
public class LinkingResourceContext extends LinkingResourceHandler {

	public LinkingResourceContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	@Override
	protected Optional<CompromisedLinkingResource> attackLinkingResource(final LinkingResource linking,
			final CredentialChange change, final EObject source, Attacker attacker) {
		final var credentials = this.getCredentials(change);

		ListOperations listHelper = new ListOperations();

		// If only partial lists are returned, this is executed until all lists are
		// returned or a vulnerable component is found
		while (!listHelper.returnedAllElements()) {
			for (List<UsageSpecification> credential : listHelper.calculateLists(credentials, attacker)) {
				final var result = this.queryAccessForEntity(linking, credential);
				if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
					final var sourceList = this.createSource(source, credential);
					final var compromised = HelperCreationCompromisedElements.createCompromisedLinking(linking,
							sourceList);
					return Optional.of(compromised);
				}
			}
		}
		return Optional.empty();
	}

}
