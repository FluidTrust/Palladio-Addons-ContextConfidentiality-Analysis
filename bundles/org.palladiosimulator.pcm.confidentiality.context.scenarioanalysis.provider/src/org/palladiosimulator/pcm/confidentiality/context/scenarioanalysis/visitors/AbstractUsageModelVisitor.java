package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.usagemodel.Branch;
import org.palladiosimulator.pcm.usagemodel.BranchTransition;
import org.palladiosimulator.pcm.usagemodel.Delay;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.pcm.usagemodel.Loop;
import org.palladiosimulator.pcm.usagemodel.ScenarioBehaviour;
import org.palladiosimulator.pcm.usagemodel.Start;
import org.palladiosimulator.pcm.usagemodel.Stop;
import org.palladiosimulator.pcm.usagemodel.util.UsagemodelSwitch;

/**
 * Abstract visitor which visits for a {@link ScenarioBehaviour} each contained action. For each
 * Object a List is propagated. The class is based on the UsageModelVisitor of the solver bundle
 *
 * @author Koziolek, Martens, majuwa
 *
 */
public class AbstractUsageModelVisitor<T> extends UsagemodelSwitch<Set<T>> {

    protected static Logger logger = Logger.getLogger(AbstractUsageModelVisitor.class.getName());

    /*
     * (non-Javadoc)
     * 
     * @see org.palladiosimulator.pcm.usagemodel.util.UsagemodelSwitch#caseScenarioBehaviour(org.
     * palladiosimulator.pcm.usagemodel.ScenarioBehaviour)
     */
    @Override
    public Set<T> caseScenarioBehaviour(final ScenarioBehaviour object) {
        logger.debug("VisitScenarioBehaviour");
        return this.doSwitch(this.getStartAction(object));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.palladiosimulator.pcm.usagemodel.util.UsagemodelSwitch#caseStart(org.palladiosimulator.
     * pcm.usagemodel.Start)
     */
    @Override
    public Set<T> caseStart(final Start object) {
        logger.debug("VisitStart");
        return this.doSwitch(object.getSuccessor());
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.palladiosimulator.pcm.usagemodel.util.UsagemodelSwitch#caseStop(org.palladiosimulator.pcm
     * .usagemodel.Stop)
     */
    @Override
    public Set<T> caseStop(final Stop object) {
        logger.debug("VisitStop");
        return new HashSet<>();
    }

    @Override
    public Set<T> caseBranch(final Branch object) {
        logger.debug("VisitBranch");
        final EList<BranchTransition> btList = object.getBranchTransitions_Branch();
        for (final BranchTransition bt : btList) {
            this.doSwitch(bt.getBranchedBehaviour_BranchTransition());
        }
        return this.doSwitch(object.getSuccessor());
    }

    /*
     * (non-Javadoc)
     *
     * @see org.palladiosimulator.pcm.usagemodel.util.UsagemodelSwitch#caseEntryLevelSystemCall(org.
     * palladiosimulator.pcm.usagemodel.EntryLevelSystemCall)
     */
    @Override
    public Set<T> caseEntryLevelSystemCall(final EntryLevelSystemCall elsc) {
        return this.doSwitch(elsc.getSuccessor());

    }

    @Override
    public Set<T> caseDelay(final Delay object) {
        logger.debug("VisitDelay");
        return this.doSwitch(object.getSuccessor());

    }

    @Override
    public Set<T> caseLoop(final Loop object) {
        logger.debug("VisitLoop");
        final Set<T> objects = this.doSwitch(object.getBodyBehaviour_Loop());
        objects.addAll(this.doSwitch(object.getSuccessor()));
        return objects;
    }

    /**
     * @param behaviour
     * @return
     */
    private Start getStartAction(final ScenarioBehaviour behaviour) {
        return behaviour.getActions_ScenarioBehaviour().stream().filter(Start.class::isInstance).map(Start.class::cast)
                .findAny().get();
    }

}
