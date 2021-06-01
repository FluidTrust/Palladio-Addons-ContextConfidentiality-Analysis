package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.seff.AbstractBranchTransition;
import org.palladiosimulator.pcm.seff.AbstractInternalControlFlowAction;
import org.palladiosimulator.pcm.seff.AcquireAction;
import org.palladiosimulator.pcm.seff.BranchAction;
import org.palladiosimulator.pcm.seff.CollectionIteratorAction;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.seff.ForkAction;
import org.palladiosimulator.pcm.seff.GuardedBranchTransition;
import org.palladiosimulator.pcm.seff.InternalAction;
import org.palladiosimulator.pcm.seff.LoopAction;
import org.palladiosimulator.pcm.seff.ProbabilisticBranchTransition;
import org.palladiosimulator.pcm.seff.ReleaseAction;
import org.palladiosimulator.pcm.seff.ResourceDemandingBehaviour;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.seff.SetVariableAction;
import org.palladiosimulator.pcm.seff.StartAction;
import org.palladiosimulator.pcm.seff.StopAction;
import org.palladiosimulator.pcm.seff.seff_reliability.RecoveryAction;
import org.palladiosimulator.pcm.seff.util.SeffSwitch;

/**
 * Visitor that builds the computed usage and computed allocation contexts.
 *
 * @author Koziolek, Martens, Lankin, Brosch
 *
 */
public class AbstractSeffVisitor<T> extends SeffSwitch<Set<T>> {

    /**
     * Logging functionality.
     */
    protected static Logger logger = Logger.getLogger(AbstractSeffVisitor.class.getName());

    /**
     * Handles recovery block actions.
     *
     * This is a workaround implementing the case for the base class of the RecoveryBlockAction
     * type, as the type itself is not directly in the SEFF package and thus not handled by the
     * SeffSwitch.
     *
     * @param action
     *            the recovery block action
     * @return the recovery block action
     */
    @Override
    public Set<T> caseAbstractInternalControlFlowAction(final AbstractInternalControlFlowAction action) {
        if (action instanceof RecoveryAction) {
            logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
            return this.doSwitch(action.getSuccessor_AbstractAction());
        } else {
            return null;
        }
    }

    /**
     * Handles acquire actions.
     *
     *
     *
     * @param action
     *            the acquire action
     * @return the acquire action
     */
    @Override
    public Set<T> caseAcquireAction(final AcquireAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        return this.doSwitch(action.getSuccessor_AbstractAction());

    }

    /**
     * Handles branch actions.
     *
     * Proceeds with the inner branch transitions, then goes to the next action.
     *
     * @param action
     *            the branch action
     * @return the branch action
     */
    @Override
    public Set<T> caseBranchAction(final BranchAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        final EList<AbstractBranchTransition> abtList = action.getBranches_Branch();
        final var list = new HashSet<T>();
        for (final AbstractBranchTransition abt : abtList) {
            list.addAll(this.doSwitch(abt));
        }
        list.addAll(this.doSwitch(action.getSuccessor_AbstractAction()));
        return list;
    }

    /**
     * Handles collection iterator actions.
     *
     * Invokes the collectionIteratorHandler, then goes to the next action.
     *
     * @param action
     *            the collection iterator action
     * @return the collection iterator action
     */
    @Override
    public Set<T> caseCollectionIteratorAction(final CollectionIteratorAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles external call actions.
     *
     * Invokes the externalCallHandler, then goes to the next action.
     *
     * @param action
     *            the external call action
     * @return the external call action
     */
    @Override
    public Set<T> caseExternalCallAction(final ExternalCallAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles fork actions.
     *
     * Invokes the forkActionHandler, then goes to the next action.
     *
     * @param action
     *            the fork action
     * @return the fork action
     */
    @Override
    public Set<T> caseForkAction(final ForkAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles guarded branch transitions.
     *
     * Invokes the guardedBranchHandler.
     *
     * @param transition
     *            the branch transition
     * @return the branch transition
     */
    @Override
    public Set<T> caseGuardedBranchTransition(final GuardedBranchTransition transition) {
        return new HashSet<>();
    }

    /**
     * Handles internal actions.
     *
     * Invokes the internalActionHandler, then goes to the next action.
     *
     * @param action
     *            the internal action
     * @return the internal action
     */
    @Override
    public Set<T> caseInternalAction(final InternalAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"("
                + action.getId() + ")");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles loop actions.
     *
     * Invokes the loopActionHandler, then goes to the next action.
     *
     * @param action
     *            the loop action
     * @return the loop action
     */
    @Override
    public Set<T> caseLoopAction(final LoopAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles probabilistic branch transitions.
     *
     * Invokes the probabilisticBranchHandler, then goes to the next action.
     *
     * @param transition
     *            the branch transition
     * @return the branch transition
     */
    @Override
    public Set<T> caseProbabilisticBranchTransition(final ProbabilisticBranchTransition transition) {
        return new HashSet<>();
    }

    /**
     * Handles release actions.
     *
     * Nothing to do for the dependency solver. Just goes to the next action.
     *
     * @param action
     *            the release action
     * @return the release action
     */
    @Override
    public Set<T> caseReleaseAction(final ReleaseAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles resource demanding behaviours.
     *
     * Goes to the first action within the behaviour.
     *
     * @param behaviour
     *            the resource demanding behaviour
     * @return the resource demanding behaviour
     */
    @Override
    public Set<T> caseResourceDemandingBehaviour(final ResourceDemandingBehaviour behaviour) {
        return this.doSwitch(this.getStartAction(behaviour));
    }

    /**
     * Handles resource demanding seffs.
     *
     * Goes to the first action within the seff.
     *
     * @param behaviour
     *            the resource demanding seff
     * @return the resource demanding seff
     */
    @Override
    public Set<T> caseResourceDemandingSEFF(final ResourceDemandingSEFF behaviour) {
        final ResourceDemandingBehaviour rdb = behaviour;
        return this.doSwitch(this.getStartAction(rdb));
    }

    /**
     * Handles set variable actions.
     *
     * Invokes the setVariableHandler, then goes to the next action.
     *
     * @param action
     *            the set variable action
     * @return the set variable action
     */
    @Override
    public Set<T> caseSetVariableAction(final SetVariableAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\" ("
                + action.getId() + ")");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles start actions.
     *
     * Nothing to do for the dependency solver. Just goes to the next action.
     *
     * @param action
     *            the start action
     * @return the start action
     */
    @Override
    public Set<T> caseStartAction(final StartAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\" ("
                + action.getId() + ")");
        return this.doSwitch(action.getSuccessor_AbstractAction());
    }

    /**
     * Handles stop actions.
     *
     * Saves the contexts that have been created for the surrounding resource demanding seff.
     *
     * @param action
     *            the stop action
     * @return the stop action
     */
    @Override
    public Set<T> caseStopAction(final StopAction action) {
        logger.debug("Visit " + action.getClass().getSimpleName() + " \"" + action.getEntityName() + "\"("
                + action.getId() + ")");
        return new HashSet<>();
    }

    /**
     * Searches for a StartAction within the chain of AbstractActions of the behaviour and returns
     * it.
     *
     * @param behaviour
     *            the behaviour
     * @return the start action
     */
    private StartAction getStartAction(final ResourceDemandingBehaviour behaviour) {
        return behaviour.getSteps_Behaviour().stream().filter(StartAction.class::isInstance)
                .map(StartAction.class::cast).findAny().get();
    }
}
