package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;

public class ImpactOnExistingAnalysis extends MitigationTravelPlanner {

	public ImpactOnExistingAnalysis() {
		this.PATH_ATTACKER = "mitigationModels/compositeTravelPlanner/tests/06/test_model.attacker";
		this.PATH_CONTEXT = "mitigationModels/compositeTravelPlanner/tests/06/test_model.context";
		this.PATH_MODIFICATION = "mitigationModels/compositeTravelPlanner/tests/06/test_model.kamp4attackmodificationmarks";
	}

	@Test
	void propagation() {
		runAnalysis();

		var change = getCredentials();

		//encryption should not have any impact on this values
		assertEquals(4, change.getCompromisedassembly().size());
		assertEquals(0, change.getCompromisedlinkingresource().size());
		assertEquals(1, change.getCompromisedresource().size());
		assertEquals(4, change.getCompromisedservice().size());
		assertEquals(0, change.getContextchange().size());
		assertEquals(0, change.getCompromiseddata().size());

		assertTrue(checkAssembly(change));
		assertTrue(checkResource(change));
		assertTrue(checkServiceRestriction(change));

	}

	@Override
	protected boolean assemblyNameMatch(String name) {
		var set = Set.of("Assembly_Airline_Start", "Assembly_Airline", "Assembly_AirlineLogic", "Assembly_FlightsDB");
		return set.contains(name);
	}

	@Override
	protected boolean resourceNameMatch(String name) {
		var set = Set.of("AirlineServer");
		return set.contains(name);
	}

	@Override
	protected boolean checkServiceRestriction(ServiceRestriction servicerestriction1) {
		var setAssembly = Set.of("Assembly_Airline_Start", "Assembly_Airline", "Assembly_AirlineLogic", "Assembly_FlightsDB");

		var equalAssembly = setAssembly.contains(servicerestriction1.getAssemblycontext().getEntityName());
		if (!equalAssembly) {
			return equalAssembly;
		}
		var setServices = Set.of("_DTSesGzuEeqas-IKudlqKw", "_DTq5MGzuEeqas-IKudlqKw", "_ND1akG3REeqmcoyeW2eH2g",
				"_NqqKAG3REeqmcoyeW2eH2g");
		// the pay commision method is not reachable since it is in another network
		var returnValue = setServices.contains(servicerestriction1.getService().getId());
		return returnValue;
	}
}
