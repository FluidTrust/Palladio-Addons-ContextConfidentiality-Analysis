package edu.kit.ipd.sdq.attacksurface.graph.tests;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;

public abstract class AttackGraphCreationTest extends AbstractChangeTests {

    public AttackGraphCreationTest() {
        this.PATH_ATTACKER = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.system";
        this.PATH_ALLOCATION = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.repository";
        this.PATH_USAGE = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels-surface/DesignOverviewDiaModel/My.resourceenvironment";
    }

}
