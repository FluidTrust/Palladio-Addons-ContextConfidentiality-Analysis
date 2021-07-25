package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_OUTPUT;

import java.util.Objects;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.ui.console.ConsolePlugin;
import org.eclipse.ui.console.MessageConsole;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.OutputPartition;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

/**
 * Job to output the results of the analysisWorkflow on the running Eclipse console instance
 *
 * @author majuwa
 * @author mirko
 *
 */
public class OutputScenarioJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    private MDSDBlackboard blackboard;

    // FIXME adapt to attackeranalysis
    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var partition = (OutputPartition) this.blackboard.getPartition(PARTITION_ID_OUTPUT);
        final var myConsole = findConsole("pcm.confidentiality.context.analysis.launcher.console");
        final var out = myConsole.newMessageStream();

        for (final var result : partition.getAnalysisResults().getScenariooutput()) {
            out.print(result.getScenario().getEntityName());
            out.print(": ");
//            out.println(Boolean.toString(result.isResult()));
        }

//		if (blackboard.getSolution() != null) {
//
//			MessageConsole myConsole = findConsole(PartitionConstants.CONSOLE_ID.getConstant());
//			MessageConsoleStream out = myConsole.newMessageStream();
//			if (blackboard.getSolution().isSuccess()) {
//				for (Entry<String, String> t : blackboard.getQuery().getResultVars().entrySet()) {
//
//					out.print(t.getKey().toString() + " ; ");
//					out.println(Objects.toString(blackboard.getSolution().get(t.getValue())));
//
//				}
//			} else {
//				out.println("Solution has not succeeded");
//			}
//		}
    }

    @Override
    public void cleanup(final IProgressMonitor monitor) throws CleanupFailedException {
        // ignored
    }

    @Override
    public String getName() {
        return "Job that outputs result on Eclipse console";
    }

    private MessageConsole findConsole(final String name) {
        final var plugin = ConsolePlugin.getDefault();
        final var conMan = plugin.getConsoleManager();
        for (final org.eclipse.ui.console.IConsole console1 : conMan.getConsoles()) {
            if (Objects.equals(name, console1.getName())) {
                return (MessageConsole) console1;
            }
        }
        /* no console found, so create a new one */
        final var myConsole = new MessageConsole(name, null);
        conMan.addConsoles(new org.eclipse.ui.console.IConsole[] { myConsole });
        return myConsole;
    }

    @Override
    public void setBlackboard(final MDSDBlackboard blackboard) {
        this.blackboard = blackboard;

    }

//	public void setBlackboard(AnalysisBlackboard blackboard) {
//		this.blackboard = blackboard;
//	}

}
