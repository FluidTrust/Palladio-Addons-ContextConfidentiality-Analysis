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
public abstract class BankBaseTest extends BaseTestScenario {

    private static final String PATH_ASSEMBLY = "bank/newSystem.system";
    private static final String PATH_REPOSITORY = "bank/newRepository.repository";
    private static final String PATH_USAGE = "bank/newUsageModel.usagemodel";
    private static final String PATH_CONTEXT = "bank/abac.context";

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
