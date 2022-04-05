package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies;

import java.util.ArrayList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.BaseTestScenario;

public class ScalabilityBaseTest extends BaseTestScenario {
    private static final String PATH_ASSEMBLY = "scalability/scalability.system";
    private static final String PATH_REPOSITORY = "scalability/scalability.repository";
    private static final String PATH_USAGE = "scalability/scalability.usagemodel";
    private static final String PATH_CONTEXT = "scalability/scalability.context";

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
