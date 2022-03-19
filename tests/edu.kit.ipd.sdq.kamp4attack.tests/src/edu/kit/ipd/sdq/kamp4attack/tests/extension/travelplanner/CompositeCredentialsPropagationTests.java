package edu.kit.ipd.sdq.kamp4attack.tests.extension.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;

public class CompositeCredentialsPropagationTests extends CompositeTravelPlannerCaseStudy {

	public CompositeCredentialsPropagationTests() {
		this.PATH_ATTACKER = "compositeTravelPlanner/tests/03/test_model.attacker";
		this.PATH_CONTEXT = "compositeTravelPlanner/tests/03/test_model.context";
		this.PATH_MODIFICATION = "compositeTravelPlanner/tests/03/test_model.kamp4attackmodificationmarks";
	}

	@Test
	void propagation() {
		runAnalysis();

		var change = getCredentials();

		assertEquals(5, change.getCompromisedassembly().size());
		assertEquals(0, change.getCompromisedlinkingresource().size());
		assertEquals(1, change.getCompromisedresource().size());
		assertEquals(6, change.getCompromisedservice().size());
		assertEquals(2, change.getContextchange().size());
		assertEquals(6, change.getCompromiseddata().size());

		assertTrue(checkAssembly(change));
		assertTrue(checkResource(change));
		assertTrue(checkContext(change));
		assertTrue(checkServiceRestriction(change));

	}

	@Override
	protected boolean assemblyNameMatch(String name) {
		var set = Set.of("Assembly_TravelPlanner", "Assembly_CreditCardCenter", "Assembly_CreditCardCenterDB",
				"Assembly_CreditCardCenterLogic", "Assembly_TravelPlannerLogic");
		return set.contains(name);
	}

	@Override
	protected boolean resourceNameMatch(String name) {
		var set = Set.of("MobilePhone");
		return set.contains(name);
	}

	@Override
	protected boolean checkAttributeUsage(UsageSpecification usage) {
		var attributeEquals = usage.getAttribute().getId().equals("_fG18ovXoEeub3tcXgMY_nQ");
		if (!attributeEquals) {
			return attributeEquals;
		}
		var set = Set.of("_haahwPXoEeub3tcXgMY_nQ", "_cvu-oDjAEey9mszNksodxw");
		return set.contains(usage.getAttributevalue().getId());
	}

	@Override
	protected boolean checkServiceRestriction(ServiceRestriction servicerestriction1) {
		var setAssembly = Set.of("Assembly_TravelPlanner", "Assembly_CreditCardCenter", "Assembly_CreditCardCenterDB",
				"Assembly_CreditCardCenterLogic", "Assembly_TravelPlannerLogic");

		var equalAssembly = setAssembly.contains(servicerestriction1.getAssemblycontext().getEntityName());
		if (!equalAssembly) {
			return equalAssembly;
		}
		var setServices = Set.of("_62zh8GzqEeqas-IKudlqKw", "_JDFpUG3OEeqmcoyeW2eH2g", "_J3zDwG3OEeqmcoyeW2eH2g",
				"_VqWSYGzqEeqas-IKudlqKw", "_VvG2kGzqEeqas-IKudlqKw");
		// the pay commision method is not reachable since it is in another network
		var returnValue = setServices.contains(servicerestriction1.getService().getId());
		return returnValue;
	}
}
