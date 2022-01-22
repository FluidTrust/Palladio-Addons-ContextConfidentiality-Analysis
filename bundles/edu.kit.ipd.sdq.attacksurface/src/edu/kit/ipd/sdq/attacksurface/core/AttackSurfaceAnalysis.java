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
import org.palladiosimulator.pcm.repository.BasicComponent;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.LinkingPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.kamp.propagation.AbstractChangePropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.core.CacheVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl;

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
    //TODO move this "element" to the meta
    private AssemblyContext criticalAssembly; 
    
    private AttackDAG attackDAG;

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
        
        //TODO adapt to get critical element from surface attacker, this is just for initial testing ////////////////
        this.criticalAssembly = board.getAssembly().getAssemblyContexts__ComposedStructure()
        		.stream()
        		.filter(a -> a.getEntityName().equals("Assembly_Critical"))
        		.findAny()
        		.orElse(null);
        if (this.criticalAssembly == null) {
        	throw new IllegalStateException("no \"Assembly_Critical\" assembly context found!");
        }
        this.changePropagationDueToCredential.getCompromisedassembly(); //TODO how to compromise component
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        this.attackDAG = new AttackDAG(this.criticalAssembly);
        
        
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
    	//TODO adapt!
    	
    	final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getSurfaceattackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps().clear();

        for (final var attacker : attackers) {
            final var localAttacker = attacker.getAffectedElement();

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

            // convert affectedAssemblyContexts to changes
            var assemblyHandler = new AssemblyContextHandler(board, new DataHandlerAttacker(this.changePropagationDueToCredential)) {
                @Override
                protected Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
                        EObject source){
                    final var compromisedComponent = KAMP4attackModificationmarksFactory.eINSTANCE
                            .createCompromisedAssembly();
                    compromisedComponent.setAffectedElement(component);
                    return Optional.of(compromisedComponent);
                }
            };

            assemblyHandler.attackAssemblyContext(localAttacker.getAttacker().getCompromisedComponents(),
                    this.changePropagationDueToCredential, null);




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

	private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
		//TODO implement
		
		//TODO adapt to new analysis
		final var list = new ArrayList<AssemblyContextPropagation>(); //TODO export ok? so far ok
        list.add(new AssemblyContextPropagationContext(board, this.changePropagationDueToCredential, this.criticalAssembly));
        //list.add(new AssemblyContextPropagationVulnerability(board)); //TODO add vuln.
        for (final var analysis : list) { //TODO adapt
            analysis.calculateAssemblyContextToAssemblyContextPropagation(); 
            //TODO add others
        }
    }

}
