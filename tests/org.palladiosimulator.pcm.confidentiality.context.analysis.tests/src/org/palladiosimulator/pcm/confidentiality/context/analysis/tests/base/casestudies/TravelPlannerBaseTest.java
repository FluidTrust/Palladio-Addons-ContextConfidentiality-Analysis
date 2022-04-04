package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies;

import java.util.ArrayList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.BaseTestScenario;

/**
 * Setting URL for TravelPlanner Case Study
 *
 * @author majuwa
 *
 */
public class TravelPlannerBaseTest extends BaseTestScenario {

    private static final String PATH_ASSEMBLY = "travelplanner/default.system";
    private static final String PATH_REPOSITORY = "travelplanner/default.repository";
    private static final String PATH_USAGE = "travelplanner/default.usagemodel";
    private static final String PATH_CONTEXT = "travelplanner/Scenarios/test_scenarios.context";

    @Override
    protected List<String> getModelsPath() {
        final var list = new ArrayList<String>();

        list.add(PATH_USAGE);
        list.add(PATH_ASSEMBLY);
        list.add(PATH_REPOSITORY);
        list.add(PATH_CONTEXT);

        return list;
    }

}
