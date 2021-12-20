package edu.kit.ipd.sdq.attacksurface.core;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.CacheVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
/*import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;*/ //TODO
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Entry point for attack surface propagation
 *
 * @author majuwa
 * @author ugnwq
 */

@Component
public class AttackSurfaceAnalysis implements AbstractChangePropagationAnalysis<BlackboardWrapper> {

    private CredentialChange changePropagationDueToCredential;

    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
        CacheCompromised.instance().register(this.changePropagationDueToCredential);
        // prepare

        createInitialStructure(board); //TODO implement

        
        //TODO adapt
        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            /*TODO calculateAndMarkLinkingPropagation(board);
            calculateAndMarkResourcePropagation(board);*/
            calculateAndMarkAssemblyPropagation(board);

        } while (this.changePropagationDueToCredential.isChanged());

        // Clear caches
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
    }

    private void createInitialStructure(BlackboardWrapper board) {
		//TODO implement
		
	}

	private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
		//TODO implement
		
		/*final var list = new ArrayList<AssemblyContextPropagation>(); //TODO export ok?
        list.add(new AssemblyContextPropagationContext(board));
        list.add(new AssemblyContextPropagationVulnerability(board));
        for (final var analysis : list) {
            analysis.calculateAssemblyContextToContextPropagation(this.changePropagationDueToCredential); //TODO adapt
        }*/
    }

}
