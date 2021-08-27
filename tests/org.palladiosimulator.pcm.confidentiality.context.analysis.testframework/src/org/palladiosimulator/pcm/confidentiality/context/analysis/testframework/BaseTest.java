package org.palladiosimulator.pcm.confidentiality.context.analysis.testframework;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.resource.Resource;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.XACMLPDP;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;

import tools.mdsd.library.standalone.initialization.StandaloneInitializationException;

public abstract class BaseTest {
    protected Evaluate eval;

    protected final String pathXACML = "test.xml";

    @BeforeAll
    static void init() throws StandaloneInitializationException {
        TestInitializer.init();
    }

    private Resource loadResource(final ResourceSet resourceSet, final URI path) {
        return resourceSet.getResource(path, true);
    }

    /**
     * Gives a list with the relative path as {@link String} to the models used for testing
     *
     * @return {@link List} of Strings
     */
    protected abstract List<String> getModelsPath();

    /**
     * Method to assign loaded resources to values
     *
     */
    protected abstract void assignValues(List<Resource> list);

    protected <T extends EObject> T getModel(final List<Resource> resources, final Class<T> classObject) {
        final var object = resources.stream().filter(e -> classObject.isInstance(e.getContents().get(0))).findAny();
        if (object.isEmpty()) {
            fail("Class not found " + classObject);
        }
        return classObject.cast(object.get().getContents().get(0));
    }

    @BeforeEach
    protected void loadModels() throws IOException {
        final var listResources = new ArrayList<Resource>();
        final var resourceSet = new ResourceSetImpl();

        final var listModels = getModelsPath();
        for (final var model : listModels) {
            listResources.add(loadResource(resourceSet, TestInitializer.getModelURI(model)));
        }

        assignValues(listResources);

        EcoreUtil.resolveAll(resourceSet);
    }

    @BeforeEach
    protected void initEval() {
        this.eval = new XACMLPDP();
        this.eval.initialize(this.pathXACML);
    }

    protected abstract void generateXML();

    @AfterEach
    protected void shutdownEval() {
        this.eval.shutdown();
        var file = new File(this.pathXACML);
        assert file.delete();

    }



}
