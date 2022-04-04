package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies;

import java.util.ArrayList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.BaseTestScenario;

/**
 * Setting URL to test models for the maintenance scenario
 *
 * @author majuwa
 *
 */
public abstract class MaintenanceBaseTest extends BaseTestScenario {

    private static final String PATH_ASSEMBLY = "maintenance/maintenanceScenario.system";
    private static final String PATH_REPOSITORY = "maintenance/maintenanceScenario.repository";
    private static final String PATH_USAGE = "maintenance/maintenanceScenario.usagemodel";
    private static final String PATH_CONTEXT = "maintenance/maintenanceScenario.context";

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
