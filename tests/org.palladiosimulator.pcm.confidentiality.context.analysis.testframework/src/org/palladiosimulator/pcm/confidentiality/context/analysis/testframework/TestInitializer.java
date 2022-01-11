package org.palladiosimulator.pcm.confidentiality.context.analysis.testframework;

import javax.xml.bind.Marshaller;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels.Activator;

import jakarta.activation.DataSource;
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
                .registerProjectURI(DataSource.class, "external-dependencies")
                .registerProjectURI(org.glassfish.hk2.osgiresourcelocator.Activator.class,
                        "org.glassfish.hk2.osgi-resource-locator")
                .registerProjectURI(javax.xml.bind.JAXB.class, "jakarta.xml.bind")
                .registerProjectURI(com.sun.xml.bind.v2.ClassFactory.class, "com.sun.xml.bind")
//                .registerProjectURI(com.att.research.xacmlatt.pdp.policy.PolicySet.class, "external-dependencies")
                .registerProjectURI(Marshaller.class, "external-dependencies")
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
