package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Map;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.resource.Resource;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.eclipse.emf.ecore.xmi.impl.XMIResourceFactoryImpl;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerPackage;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.AttackerAnalysisWorkflow;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.repository.RepositoryPackage;

import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.AssemblyChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class TestModels {
	static IProgressMonitor monitor;

	@BeforeAll
	static void loadModels() throws JobFailedException, UserCanceledException {

		RepositoryPackage.eINSTANCE.eClass();
		var resourceRegistry = Resource.Factory.Registry.INSTANCE;
		final Map<String, Object> map = resourceRegistry.getExtensionToFactoryMap();
		map.put("*", new XMIResourceFactoryImpl());
		AttackerPackage.eINSTANCE.eClass();
		monitor = new IProgressMonitor() {

			@Override
			public void worked(int work) {
				// TODO Auto-generated method stub

			}

			@Override
			public void subTask(String name) {
				// TODO Auto-generated method stub

			}

			@Override
			public void setTaskName(String name) {
				// TODO Auto-generated method stub

			}

			@Override
			public void setCanceled(boolean value) {
				// TODO Auto-generated method stub

			}

			@Override
			public boolean isCanceled() {
				// TODO Auto-generated method stub
				return false;
			}

			@Override
			public void internalWorked(double work) {
				// TODO Auto-generated method stub

			}

			@Override
			public void done() {
				// TODO Auto-generated method stub

			}

			@Override
			public void beginTask(String name, int totalWork) {
				// TODO Auto-generated method stub

			}
		};

	}

	@Test
	void test() throws JobFailedException, UserCanceledException {
		var config = new AttackerAnalysisWorkflowConfig();
		config.setAdversaryModel(URI.createFileURI("models/GetAssemblyContext/my.attacker"));
		config.setAllocationModel(URI.createFileURI("models/GetAssemblyContext/newAllocation.allocation"));
		config.setContextModel(URI.createFileURI("models/GetAssemblyContext/My.context"));
		config.setModificationModel(URI.createFileURI("models/GetAssemblyContext/My.kamp4attackmodificationmarks"));
		config.setRepositoryModel(URI.createFileURI("models/GetAssemblyContext/newRepository.repository"));
		var steps = executeConfig(config).getChangePropagationSteps();
		
		
		assertTrue(steps.stream().allMatch(e -> e instanceof CompromisedAssembly || e instanceof CredentialChange || e instanceof CompromisedResource));
	}

	private AbstractKAMP4attackModificationRepository<?> executeConfig(AttackerAnalysisWorkflowConfig config) throws JobFailedException, UserCanceledException {
		var flow = new AttackerAnalysisWorkflow(config);
		var blackboard = new MDSDBlackboard();
		flow.setBlackboard(blackboard);
		EcoreUtil.resolveAll(((ModificationMarkPartition) blackboard.getPartition(PartitionConstants.PARTITION_ID_MODIFICATION))
        .getModificationRepository().eResource());
		flow.execute(monitor);
		return ((ModificationMarkPartition) blackboard.getPartition(PartitionConstants.PARTITION_ID_MODIFICATION))
        .getModificationRepository();
	}

}
