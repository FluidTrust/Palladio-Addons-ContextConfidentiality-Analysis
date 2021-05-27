package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.ecore.resource.Resource;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

public abstract class BaseTestScenario extends BaseTest {

    private static final String PATH_ASSEMBLY = "travelplanner/default.system";
    private static final String PATH_REPOSITORY = "travelplanner/default.repository";
    private static final String PATH_USAGE = "travelplanner/default.usagemodel";
    private static final String PATH_CONTEXT = "travelplanner/Scenarios/test_model_02.context";
    protected Repository repo;
    protected UsageModel usage;
    protected System assembly;
    protected ConfidentialAccessSpecification context;
    
    @Override
    protected List<String> getModelsPath(){
        var list = new ArrayList<String>();
        
        list.add(PATH_USAGE);
        list.add(PATH_ASSEMBLY);
        list.add(PATH_REPOSITORY);
        list.add(PATH_CONTEXT);
        
        return list;
    }

    protected void assignValues(List<Resource> list) {
        this.assembly = this.getModel(list, System.class);
        this.repo = this.getModel(list, Repository.class);
        this.context = this.getModel(list, ConfidentialAccessSpecification.class);
        this.usage = this.getModel(list, UsageModel.class);
    }
   
    


}
