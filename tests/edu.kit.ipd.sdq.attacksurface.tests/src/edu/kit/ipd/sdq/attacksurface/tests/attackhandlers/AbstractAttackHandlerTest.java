package edu.kit.ipd.sdq.attacksurface.tests.attackhandlers;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.tests.AbstractModelTest;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AbstractAttackHandlerTest extends AbstractModelTest {
    
    public AbstractAttackHandlerTest() {
        //TODO adapt
        this.PATH_ATTACKER = "simpleAttackmodels/DesignOverviewDiaModel/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels/DesignOverviewDiaModel/My.system";
        this.PATH_ALLOCATION = "simpleAttackmodels/DesignOverviewDiaModel/My.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels/DesignOverviewDiaModel/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels/DesignOverviewDiaModel/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels/DesignOverviewDiaModel/My.repository";
        this.PATH_USAGE = "simpleAttackmodels/DesignOverviewDiaModel/My.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels/DesignOverviewDiaModel/My.resourceenvironment";
    }
}
