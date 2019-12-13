package org.palladiosimulator.pcm.confidentiality.context.analysis.provider;

import java.util.Objects;

import org.eclipse.emf.common.util.URI;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.Analysis;
import org.palladiosimulator.pcm.confidentiality.context.analysis.provider.helper.ModelLoader;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

@Component
public class AnalysisImpl implements Analysis{

    @Override
    public boolean testArchitecture(String pathContext, String... pathScenarios) {
        Objects.requireNonNull(pathContext);
        Objects.requireNonNull(pathScenarios); 
        var urlContext = URI.createFileURI(pathContext);
        var urlUsageModel = URI.createFileURI(pathScenarios[0]);
        
        var loader = new ModelLoader();
        
        var context = loader.getContextModel(urlContext);
        var usage = loader.getUsageModel(urlUsageModel);
        
        
        
        
        return false;
    }

    
}
