package org.palladiosimulator.pcm.confidentiality.context.analysis.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.resource.Resource;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisImpl;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.UsageModel;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels.Activator;

import tools.mdsd.library.standalone.initialization.StandaloneInitializationException;
import tools.mdsd.library.standalone.initialization.StandaloneInitializerBuilder;
import tools.mdsd.library.standalone.initialization.log4j.Log4jInitilizationTask;

public class DataTest {

    private static final String PATH_ASSEMBLY = "default.system";
    private static final String PATH_ALLOCATION = "default.allocation";
    private static final String PATH_REPOSITORY = "default.repository";
    private static final String PATH_USAGE = "default.usagemodel";
    private static final String PATH_CONTEXT = "Scenarios/test_model_02.context";
    private Repository repo;
    private UsageModel usage;
    private System assembly;
    private ResourceEnvironment environment;
    private ConfidentialAccessSpecification context;
    
    private Resource loadResource(final ResourceSet resourceSet, final URI path) {
        return resourceSet.getResource(path, true);
    }
    
    @BeforeAll
    static void init() throws StandaloneInitializationException {
       StandaloneInitializerBuilder.builder().registerProjectURI(Activator.class, "org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels")    
       .addCustomTask(new Log4jInitilizationTask()).build().init();
    }
    
    public static URI getModelURI(String relativeModelPath) {
        return getRelativePluginURI("models/" + relativeModelPath);
    }

    private static URI getRelativePluginURI(String relativePath) {
        return URI.createPlatformPluginURI(
                "/org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels/" + relativePath, false);
    }
    
    @BeforeEach
    protected void loadModels() throws IOException {

//        final EPackage[] ePackages = new EPackage[] { EcorePackage.eINSTANCE, IdentifierPackage.eINSTANCE,
//                UnitsPackage.eINSTANCE, ProbfunctionPackage.eINSTANCE, PcmPackage.eINSTANCE, SeffPackage.eINSTANCE,
//                RepositoryPackage.eINSTANCE, ParameterPackage.eINSTANCE, UsagemodelPackage.eINSTANCE,
//                SystemPackage.eINSTANCE, ResourcetypePackage.eINSTANCE, ResourceenvironmentPackage.eINSTANCE,
//                AllocationPackage.eINSTANCE, StoexPackage.eINSTANCE, CorePackage.eINSTANCE,
//                /* CompletionsPackage.eINSTANCE, */ ReliabilityPackage.eINSTANCE, QosReliabilityPackage.eINSTANCE,
//                SeffReliabilityPackage.eINSTANCE, ContextPackage.eINSTANCE, SpecificationPackage.eINSTANCE,
//                AssemblyPackage.eINSTANCE};

        final var resourceSet = new ResourceSetImpl();

//        for (final EPackage ePackage : ePackages) {
//            resourceSet.getPackageRegistry().put(ePackage.getNsURI(), ePackage);
//        }
        final var resourceUsage = this.loadResource(resourceSet, getModelURI(PATH_USAGE));
        final var resourceAssembly = this.loadResource(resourceSet, getModelURI(PATH_ASSEMBLY));
        final var resourceRepository = this.loadResource(resourceSet, getModelURI(PATH_REPOSITORY));
        final var resourceContext = this.loadResource(resourceSet, getModelURI(PATH_CONTEXT));
        
        
//        final var list = new ArrayList<Resource>(resourceSet.getResources());
//        for (final var res : list) {
//            EcoreUtil.resolveAll(res);
//        }

        this.assembly = (System) resourceAssembly.getContents().get(0);
        this.context = (ConfidentialAccessSpecification) resourceContext.getContents().get(0);
        this.repo = (Repository) resourceRepository.getContents().get(0);
        this.usage = (UsageModel) resourceUsage.getContents().get(0);
        
        EcoreUtil.resolveAll(resourceSet);

    }
    
    @Test
    void test() {
        var blackBoard = new PCMBlackBoard(assembly, repo, usage);
        var analysis = new ScenarioAnalysisImpl();
        var output = analysis.runScenarioAnalysis(blackBoard, context);
        assertNotNull(output.getScenariooutput());
    }

}
