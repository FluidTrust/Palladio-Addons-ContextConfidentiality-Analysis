package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

public abstract class MitigationTravelPlanner extends AbstractChangeTests {

	public MitigationTravelPlanner() {
		this.PATH_REPOSITORY = "mitigationModels/compositeTravelPlanner/default.repository";
		this.PATH_RESOURCES = "mitigationModels/compositeTravelPlanner/default.resourceenvironment";
		this.PATH_ASSEMBLY = "mitigationModels/compositeTravelPlanner/default.system";
		this.PATH_ALLOCATION = "mitigationModels/compositeTravelPlanner/default.allocation";
	}

	@Test
	void defaultCase() {
		runAnalysis();
	}

	protected CredentialChange getCredentials() {
		assertEquals(1, this.modification.getChangePropagationSteps().size());

		var change = this.modification.getChangePropagationSteps().get(0);

		assertTrue(change instanceof CredentialChange);

		return (CredentialChange) change;

	}

	protected boolean checkAssembly(CredentialChange change) {
		return change.getCompromisedassembly().stream().map(this::mapAffectedAssembly)
				.map(AssemblyContext::getEntityName).allMatch(this::assemblyNameMatch);
	}

	protected boolean checkResource(CredentialChange change) {
		return change.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
				.map(ResourceContainer::getEntityName).allMatch(this::resourceNameMatch);
	}

	protected boolean checkLinking(CredentialChange change) {
		return change.getCompromisedlinkingresource().stream().map(CompromisedLinkingResource::getAffectedElement)
				.map(LinkingResource::getEntityName).allMatch(this::linkingResourceNameMatch);
	}

	protected boolean checkContext(CredentialChange change) {
		return change.getContextchange().stream().map(ContextChange::getAffectedElement)
				.allMatch(this::checkAttributeUsage);
	}

	protected boolean checkServiceRestriction(CredentialChange change) {
		return change.getCompromisedservice().stream().map(CompromisedService::getAffectedElement)
				.allMatch(this::checkServiceRestriction);
	}

	protected boolean assemblyNameMatch(String name) {
		fail();
		return false;
	}

	protected boolean resourceNameMatch(String name) {
		fail();
		return false;
	}

	protected boolean checkAttributeUsage(UsageSpecification usage) {
		fail();
		return false;
	}

	protected boolean checkServiceRestriction(ServiceRestriction servicerestriction1) {
		fail();
		return false;
	}

	protected boolean linkingResourceNameMatch(String name) {
		fail();
		return false;
	}

	private AssemblyContext mapAffectedAssembly(CompromisedAssembly component) {
		return component.getAffectedElement().getCompromisedComponents().get(0);
	}

}
