package edu.kit.ipd.sdq.attacksurface.core;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.CacheVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
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
    
    //TODO more general: "element", i.e. NamedEntity, ModifyEntity ?
    private AssemblyContext criticalAssembly; 
    
    private AttackDAG attackDAG;

    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance().clearCache();
        CacheLastCompromisationCausingElements.instance().reset();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
        CacheCompromised.instance().register(this.changePropagationDueToCredential);
        CacheLastCompromisationCausingElements.instance().register(this.changePropagationDueToCredential);
        
        // prepare
        createInitialStructure(board);
        this.attackDAG = new AttackDAG(this.criticalAssembly);
        
        //TODO adapt
        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            
            calculateAndMarkAssemblyPropagation(board);
            calculateAndMarkResourcePropagation(board);
            /*TODO calculateAndMarkLinkingPropagation(board);*/
        } while (this.changePropagationDueToCredential.isChanged()); 

        // Clear caches
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
        CacheVulnerability.instance().reset();
        CacheLastCompromisationCausingElements.instance().reset();
    }

    private void createInitialStructure(BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getSurfaceattackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps().clear();

        for (final var attacker : attackers) { //TODO at the moment only one attacker allowed
            final var localAttacker = attacker.getAffectedElement();
            this.criticalAssembly = localAttacker.getCriticalElement().getAssemblycontext(); //TODO more general

            final var listCredentialChanges = localAttacker.getAttacker().getCredentials()
                    .stream()
                    .map(context -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                change.setAffectedElement(context);
                return change;
            }).collect(Collectors.toList());

            this.changePropagationDueToCredential.getContextchange().addAll(listCredentialChanges);

            // convert affectedResources to changes
            final var affectedRessourcesList = localAttacker.getAttacker().
                    getCompromisedResources().stream().map(resource -> {
                final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                change.setAffectedElement(resource);
                return change;
            }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedresource().addAll(affectedRessourcesList);
            
            //TODO add all possible attacks to the attack container and the attacker
            
            // convert affectedLinkingResources to changes
            final var affectedLinkingList = localAttacker.getAttacker().getCompromisedLinkingResources().stream()
                    .map(linkingResource -> {
                        final var change = KAMP4attackModificationmarksFactory.eINSTANCE
                                .createCompromisedLinkingResource();
                        change.setAffectedElement(linkingResource);
                        return change;
                    }).collect(Collectors.toList());
            this.changePropagationDueToCredential.getCompromisedlinkingresource().addAll(affectedLinkingList);

        }
        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changePropagationDueToCredential);
		
	}
	
    /**
     * Calculates the propagation starting from {@link AssemblyContext}s. 
     * The analyses start from the critical element and try to calculate back possible attack paths to it. <br/>
     * TODO: consider credentials and propagation to other model elements except assembly contexts 
     * 
     * @param board - the model storage
     */
    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        //TODO complete implementation
        
		final var list = new ArrayList<AssemblyContextPropagation>();
        list.add(new AssemblyContextPropagationVulnerability(board, this.changePropagationDueToCredential, this.attackDAG));
        //list.add(new AssemblyContextPropagationContext(board));
        for (final var analysis : list) { //TODO adapt
            analysis.calculateAssemblyContextToAssemblyContextPropagation(); 
            //TODO add others
        }
    }
    

    private void calculateAndMarkResourcePropagation(final BlackboardWrapper board) {
        // TODO complete implementation
        
        final var list = new ArrayList<ResourceContainerPropagation>();
        list.add(new ResourceContainerPropagationVulnerability(board, this.changePropagationDueToCredential, this.attackDAG));
        //list.add(new ResourceContainerPropagationContext(board, this.changePropagationDueToCredential, this.attackDAG));
        for (final var analysis : list) { //TODO adapt
            //TODO analysis.calculateResourceContainerToLocalAssemblyContextPropagation();
            analysis.calculateResourceContainerToRemoteAssemblyContextPropagation();
            //TODO add others
        }
    }

}
