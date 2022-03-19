package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.LinkingResourceContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ResourceContainerPropagationContext extends ResourceContainerChange {

	public ResourceContainerPropagationContext(final BlackboardWrapper v, CredentialChange change) {
		super(v, change);
	}

	@Override
	protected LinkingResourceHandler getLinkingHandler() {
		return new LinkingResourceContext(this.modelStorage, new DataHandlerAttacker(this.changes));
	}

	@Override
	protected ResourceContainerHandler getResourceHandler() {
		return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.changes));
	}

	@Override
	protected AssemblyContextHandler getAssemblyHandler() {
		return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(this.changes));
	}

	@Override
	protected void handleSeff(CredentialChange changes, List<AssemblyContextDetail> components,
			ResourceContainer source) {
		// intentional blank

	}

}
