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
public abstract class UniversityGradingBaseTest extends BaseTestScenario {

    private static final String PATH_ASSEMBLY = "university/gradeManagement.system";
    private static final String PATH_REPOSITORY = "university/gradeManagement.repository";
    private static final String PATH_USAGE = "university/gradeManagement.usagemodel";
    private static final String PATH_CONTEXT = "university/gradeManagement.context";

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
