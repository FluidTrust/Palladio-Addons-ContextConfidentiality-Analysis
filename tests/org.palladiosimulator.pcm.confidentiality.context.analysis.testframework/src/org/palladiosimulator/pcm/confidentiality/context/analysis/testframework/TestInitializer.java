package org.palladiosimulator.pcm.confidentiality.context.analysis.testframework;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels.Activator;

import tools.mdsd.library.standalone.initialization.StandaloneInitializationException;
import tools.mdsd.library.standalone.initialization.StandaloneInitializerBuilder;
import tools.mdsd.library.standalone.initialization.log4j.Log4jInitilizationTask;

public class TestInitializer {

    private TestInitializer() {
        assert false;
    }

    public static void init() throws StandaloneInitializationException {
        StandaloneInitializerBuilder.builder()
                .registerProjectURI(Activator.class,
                        "org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels")
                .addCustomTask(new Log4jInitilizationTask()).build().init();
    }

    public static URI getModelURI(final String relativeModelPath) {
        return getRelativePluginURI("models/" + relativeModelPath);
    }

    private static URI getRelativePluginURI(final String relativePath) {
        return URI.createPlatformPluginURI(
                "/org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels/" + relativePath, false);
    }

}
