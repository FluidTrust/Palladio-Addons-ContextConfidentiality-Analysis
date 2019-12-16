package org.palladiosimulator.pcm.confidentiality.context.analysis.provider;

import java.util.Objects;

import org.eclipse.emf.common.util.URI;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.mdsdprofiles.api.ProfileAPI;
import org.palladiosimulator.mdsdprofiles.api.StereotypeAPI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.Analysis;
import org.palladiosimulator.pcm.confidentiality.context.analysis.provider.helper.ModelLoader;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.profile.ProfileConstants;

@Component
public class AnalysisImpl implements Analysis{

    @Override
    public boolean testArchitecture(URI urlContext, URI... urlScenarios) {
        Objects.requireNonNull(urlContext);
        Objects.requireNonNull(urlScenarios); 
        
        var loader = new ModelLoader();
        
        var context = loader.getContextModel(urlContext);
        var usage = loader.getUsageModel(urlScenarios[0]);
        var profiles = ProfileAPI.getAppliedProfiles(usage.eResource());
        usage.getUsageScenario_UsageModel().get(0);
        var element = usage.getUsageScenario_UsageModel().get(0).getScenarioBehaviour_UsageScenario().getActions_ScenarioBehaviour().get(2);
        var stero = StereotypeAPI.getAppliedStereotypes(element);
        var stero2 = StereotypeAPI.getStereotypeApplication(element, stero.get(0));
        var type = (Policy) StereotypeAPI.getTaggedValue(element, "policy", ProfileConstants.STEREOTYPE_CONTEXT);
        var contexts = type.getContexts();
        
        
        
        return false;
    }

    
}
