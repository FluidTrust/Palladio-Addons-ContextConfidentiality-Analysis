package edu.kit.ipd.sdq.kamp4attack.core;

import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;

//TODO This is probably the interesting component.

/**
 * The change propagation analysis of KAMP4APS 1. determines a seed population of affected
 * components (resp. provided roles) 2. calculates in iterations: a) inter-component propagation b)
 * intra-component propagation 3. generates internal modification marks for affected elements
 * 
 * - elements which were already part of a seed population are not further investigated
 * 
 * 
 * @author Sandro Koch
 *
 */
public class AttackPropagationAnalysis implements AbstractChangePropagationAnalysis<BlackboardWrapper> {

//    private ChangePropagationDueToHardwareChange changePropagationDueToHardwareChange;
//    private SensorChanges scenarioZero;
////    private SwitchChanges scenarioOne;
////    private BusChanges scenarioTwo;
//    private SignalInterfacePropagation siPropagation;

    @Override
    public void runChangePropagationAnalysis(BlackboardWrapper board) {
        // Setup

        // Calculate
//        do {
//            changePropagationDueToHardwareChange.setChanged(false);
//            calculateAndMarkFromStructurePropagation(board);
//            calculateAndMarkFromModulePropagation(board);
//            calculateAndMarkFromComponentPropagation(board);
//            calculateAndMarkFromInterfacePropagation(board);
//            addAllChangePropagations(board);
//        } while (changePropagationDueToHardwareChange.isChanged());
//		calculateAndMarkRampChanges(version);
//		calculateAndMarkScrewingChanges(version);

        // Update

//		IECArchitectureVersion iecVersion = BlackboardWrapper.extractIECArchitecture(version);
//		if(iecVersion.getModificationMarkRepository() != null && iecVersion.getConfiguration() != null) {
//			IECChangePropagationAnalysis iecAnalysis = new IECChangePropagationAnalysis();
//			List<IECComponent> iecSeed = new LinkedList<>();
//			for(IECModifyGlobalVariable mod : changePropagationDueToDataDependency.getGlobalVariableModifications()) {
//				iecSeed.add(mod.getAffectedElement());
//			}
//			iecAnalysis.setSeedModifications(iecSeed);
//			
//			iecAnalysis.runChangePropagationAnalysis(iecVersion);
//		}
        
    }
    
    private void calculateAndMarkToCredentialPropagation() {
        
    }


}
