package org.palladiosimulator.pcm.confidentiality.context.analysis.provider;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.modelversioning.emfprofile.registry.IProfileRegistry;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.mdsdprofiles.api.ProfileAPI;
import org.palladiosimulator.mdsdprofiles.api.StereotypeAPI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.AttackerAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.model.Context;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.profile.ProfileConstants;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.usagemodel.AbstractUserAction;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.pcm.usagemodel.Start;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

import edu.kit.kastel.scbs.confidentiality.ConfidentialitySpecification;
import edu.kit.kastel.scbs.confidentiality.adversary.Adversaries;
import edu.kit.kastel.scbs.confidentiality.adversary.Adversary;

@Component
public class AnalysisImpl implements AttackerAnalysis {

    /*
    private void iterateUsageScenario(UsageScenario scenario) {
        assert ProfileAPI.isProfileApplied(scenario.eResource(), ProfileConstants.PROFILE_NAME);
        AbstractUserAction element = findStartAction(scenario);
        Policy policy = null;
        do {
            if (StereotypeAPI.isStereotypeApplied(element, ProfileConstants.STEREOTYPE_CONTEXT)) {
                policy = (Policy) StereotypeAPI.getTaggedValue(element, ProfileConstants.POLICY_STRING,
                        ProfileConstants.STEREOTYPE_CONTEXT);
            }
            if (element instanceof EntryLevelSystemCall) {
               checkMethod((EntryLevelSystemCall) element, policy);
            }
            element = element.getSuccessor();

        } while (element != null);
    }

    private boolean checkMethod(EntryLevelSystemCall systemCall, Policy policy) {
        var operations = systemCall.getProvidedRole_EntryLevelSystemCall();
        var system = (org.palladiosimulator.pcm.system.System) EcoreUtil.getRootContainer(operations);
        
        
        return false;
    }

    private Start findStartAction(UsageScenario scenario) {
        return scenario.getScenarioBehaviour_UsageScenario().getActions_ScenarioBehaviour().stream()
                .filter(Start.class::isInstance).map(Start.class::cast).findFirst().get();
    }*/

    @Override
    public boolean runAttackerAnalysis(Repository pcm, Context context, Adversaries adversary, ConfidentialitySpecification data) {
        IProfileRegistry.eINSTANCE.getClass();
        /*
        var profiles = ProfileAPI.getAppliedProfiles(adversary.eResource());
        if(!ProfileAPI.isProfileApplied(adversary.eResource(),ProfileConstants.PROFILE_NAME))
            return false;
        
        for(Adversary attacker:adversary.getAdversaries()) {
            analysisAttacker(pcm, context, attacker, data);
        }
        
        
        return true;
        */
    }
    /*
    private void analysisAttacker(Repository pcm, Context context, Adversary adversary, ConfidentialitySpecification data) {
      //  if(StereotypeAPI.hasAppliedStereotype(adversary,)
        
    }
    */

}
