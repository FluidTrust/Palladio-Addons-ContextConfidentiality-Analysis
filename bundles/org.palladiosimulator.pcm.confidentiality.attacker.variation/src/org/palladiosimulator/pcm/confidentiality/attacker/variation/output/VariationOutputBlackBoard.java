package org.palladiosimulator.pcm.confidentiality.attacker.variation.output;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

public class VariationOutputBlackBoard extends MDSDBlackboard {
    private AttackerComponentPathDTO attackerPath;

    public final AttackerComponentPathDTO getAttackerPath() {
        return this.attackerPath;
    }

    public final void setAttackerPath(AttackerComponentPathDTO attackerPath) {
        this.attackerPath = attackerPath;
    }
}
