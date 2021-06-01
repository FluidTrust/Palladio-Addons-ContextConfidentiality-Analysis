package org.palladiosimulator.pcm.confidentiality.context.analysis.provider;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.attackeranalysis.api.AttackerAnalysis;
import org.palladiosimulator.pcm.repository.Repository;

@Component
public class AnalysisImpl implements AttackerAnalysis {

    /*
     * private void iterateUsageScenario(UsageScenario scenario) { assert
     * ProfileAPI.isProfileApplied(scenario.eResource(), ProfileConstants.PROFILE_NAME);
     * AbstractUserAction element = findStartAction(scenario); Policy policy = null; do { if
     * (StereotypeAPI.isStereotypeApplied(element, ProfileConstants.STEREOTYPE_CONTEXT)) { policy =
     * (Policy) StereotypeAPI.getTaggedValue(element, ProfileConstants.POLICY_STRING,
     * ProfileConstants.STEREOTYPE_CONTEXT); } if (element instanceof EntryLevelSystemCall) {
     * checkMethod((EntryLevelSystemCall) element, policy); } element = element.getSuccessor();
     * 
     * } while (element != null); }
     * 
     * private boolean checkMethod(EntryLevelSystemCall systemCall, Policy policy) { var operations
     * = systemCall.getProvidedRole_EntryLevelSystemCall(); var system =
     * (org.palladiosimulator.pcm.system.System) EcoreUtil.getRootContainer(operations);
     * 
     * 
     * return false; }
     * 
     * private Start findStartAction(UsageScenario scenario) { return
     * scenario.getScenarioBehaviour_UsageScenario().getActions_ScenarioBehaviour().stream()
     * .filter(Start.class::isInstance).map(Start.class::cast).findFirst().get(); }
     */

    @Override
    public boolean runAttackerAnalysis(final Repository pcm, final ConfidentialAccessSpecification context,
            final Attacker adversary) {
        return false;
        // IProfileRegistry.eINSTANCE.getClass();
        /*
         * var profiles = ProfileAPI.getAppliedProfiles(adversary.eResource());
         * if(!ProfileAPI.isProfileApplied(adversary.eResource(),ProfileConstants.PROFILE_NAME))
         * return false;
         * 
         * for(Adversary attacker:adversary.getAdversaries()) { analysisAttacker(pcm, context,
         * attacker, data); }
         * 
         * 
         * return true;
         */
    }
    /*
     * private void analysisAttacker(Repository pcm, Context context, Adversary adversary,
     * ConfidentialitySpecification data) { // if(StereotypeAPI.hasAppliedStereotype(adversary,)
     * 
     * }
     */

}
