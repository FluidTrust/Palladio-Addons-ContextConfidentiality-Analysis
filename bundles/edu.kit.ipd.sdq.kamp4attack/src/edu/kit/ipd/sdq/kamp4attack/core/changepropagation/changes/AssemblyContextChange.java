package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CompositeHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

import com.google.common.collect.Iterables;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextChange extends Change<AssemblyContext> implements AssemblyContextPropagation {

	protected AssemblyContextChange(final BlackboardWrapper v, CredentialChange change) {
		super(v, change);
	}

	@Override
	protected Collection<AssemblyContext> loadInitialMarkedItems() {
		return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, AssemblyContext.class);
	}

	/**
	 * Returns a list of all vulnerable components resulting from the current change
	 * 
	 * @return : list of vulnerable components
	 */
	protected List<AssemblyContextDetail> getCompromisedAssemblyContexts() {

		List<AssemblyContextDetail> details = new LinkedList<>();
		details.addAll(this.changes.getCompromisedassembly().stream().map(CompromisedAssembly::getAffectedElement)
				.collect(Collectors.toList()));
		return details;
	}

	@Override
	public void calculateAssemblyContextToContextPropagation() {
		final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

		final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
				.filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
				.filter(e -> listCompromisedAssemblyContexts.stream()
						.anyMatch(f -> EcoreUtil.equals(e.getAssemblycontext(), f.getCompromisedComponents().get(0))));

		updateFromContextProviderStream(this.changes, streamAttributeProvider);

	}

	@Override
	public void calculateAssemblyContextToRemoteResourcePropagation() {
		final var listCompromisedContexts = getCompromisedAssemblyContexts();

		for (final var detail : listCompromisedContexts) {
			for (AssemblyContext component : detail.getCompromisedComponents()) {

				final var connected = CompositeHelper.getAdjacentComponents(component, this.modelStorage.getAssembly());
				final var containers = connected.stream().map(this::getResourceContainer).distinct()
						.collect(Collectors.toList());
				final var handler = getRemoteResourceHandler();
				handler.attackResourceContainer(containers, this.changes, component, getAttacker());
			}
		}

	}

	private void handleSeff(final AssemblyContext soureComponent) {
		final var system = this.modelStorage.getAssembly();
		// TODO simplify stream expression directly to components!
		final var targetConnectors = CompositeHelper.getTargetedConnectors(soureComponent, system);

		final var specification = targetConnectors.stream()
				.filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), soureComponent))
				.flatMap(role -> {

					final var signatures = role.getProvidedRole_AssemblyConnector()
							.getProvidedInterface__OperationProvidedRole().getSignatures__OperationInterface();

					final var componentRepository = role.getProvidingAssemblyContext_AssemblyConnector()
							.getEncapsulatedComponent__AssemblyContext();

					if (componentRepository instanceof BasicComponent) {
						final var basicComponent = (BasicComponent) componentRepository;
						return basicComponent.getServiceEffectSpecifications__BasicComponent().stream()
								.filter(seff -> signatures.stream().anyMatch( // find only seff of
										// role
										signature -> EcoreUtil.equals(signature, seff.getDescribedService__SEFF())))

								.map(seff -> {
									final var methodspecification = StructureFactory.eINSTANCE
											.createServiceRestriction();
									methodspecification
											.setAssemblycontext(role.getProvidingAssemblyContext_AssemblyConnector());
									methodspecification.setService((ResourceDemandingSEFF) seff);
									methodspecification
											.setSignature(methodspecification.getService().getDescribedService__SEFF());
									return methodspecification;
								});

					}
					return Stream.empty();
				}).collect(Collectors.toList());
		this.handleSeff(this.changes, specification, soureComponent);
	}

	protected abstract void handleSeff(CredentialChange changes, List<ServiceRestriction> services,
			AssemblyContext source);

	@Override
	public void calculateAssemblyContextToLocalResourcePropagation() {
		final var listCompromisedContexts = getCompromisedAssemblyContexts();

		for (final var detail : listCompromisedContexts) {
			for (AssemblyContext component : detail.getCompromisedComponents()) {
				final var resource = getResourceContainer(component);
				final var handler = getLocalResourceHandler();
				handler.attackResourceContainer(List.of(resource), this.changes, component, getAttacker());
			}
		}

	}

	private ResourceContainer getResourceContainer(final AssemblyContext component) {
		final var allocationOPT = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
				.filter(allocation -> EcoreUtil.equals(allocation.getAssemblyContext_AllocationContext(), component))
				.findAny();
		if (allocationOPT.isEmpty()) {
			throw new IllegalStateException(
					"No Allocation for assemblycontext " + component.getEntityName() + " found");
		}
		return allocationOPT.get().getResourceContainer_AllocationContext();
	}

	protected abstract ResourceContainerHandler getLocalResourceHandler();

	protected abstract ResourceContainerHandler getRemoteResourceHandler();

	@Override
	public void calculateAssemblyContextToAssemblyContextPropagation() {
		final var listCompromisedContexts = getCompromisedAssemblyContexts();
		for (final var detail : listCompromisedContexts) {
			AssemblyContext component = Iterables.getLast(detail.getCompromisedComponents());
			var targetComponents = CompositeHelper.getAdjacentComponents(component, this.modelStorage.getAssembly())
					.stream().filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			var delegatedComponents = CompositeHelper
					.getDelegatedCompositeComponents(detail, this.modelStorage.getAssembly()).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			final var handler = getAssemblyHandler();
			targetComponents = CollectionHelper.removeDuplicates(targetComponents).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			delegatedComponents = CollectionHelper.removeDuplicates(delegatedComponents).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			List<AssemblyContextDetail> adjacentAssemblies = new LinkedList<>();

			// adjacent components (not part of the main composite component)
			for (AssemblyContext assembly : targetComponents) {
				if (!CompositeHelper.detailContainsAssembly(detail, assembly)) {
					adjacentAssemblies.add(CollectionHelper.createAssemblyContextDetail(assembly));
				}
			}

			// delegated components
			if (delegatedComponents.size() != 0) {
				handler.attackAssemblyContext(CompositeHelper.createDetails(detail, delegatedComponents), this.changes,
						detail, getAttacker());
			}

			// adjacent basic or composite components
			if (adjacentAssemblies.size() != 0) {
				handler.attackAssemblyContext(adjacentAssemblies, this.changes, detail, getAttacker());
			}

			this.handleSeff(component);
		}
	}

	@Override
	public void calculateAssemblyContextToGlobalAssemblyContextPropagation() {
		final var listCompromisedContexts = getCompromisedAssemblyContexts().stream().filter(this::isGlobalElement)
				.collect(Collectors.toList());

		for (var detail : listCompromisedContexts) {
			AssemblyContext component = Iterables.getLast(detail.getCompromisedComponents());
			var resourceContainer = getResourceContainer(component);
			var connectedContainers = getConnectedResourceContainers(resourceContainer);
			var reachableAssemblies = CollectionHelper.getAssemblyContext(connectedContainers,
					this.modelStorage.getAllocation());
			reachableAssemblies.addAll(
					CollectionHelper.getAssemblyContext(List.of(resourceContainer), this.modelStorage.getAllocation()));
			final var handler = getAssemblyHandler();
			reachableAssemblies = CollectionHelper.removeDuplicates(reachableAssemblies).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			var delegatedComponents = CompositeHelper
					.getDelegatedCompositeComponents(detail, this.modelStorage.getAssembly()).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			delegatedComponents = CollectionHelper.removeDuplicates(delegatedComponents).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			List<AssemblyContextDetail> adjacentAssemblies = new LinkedList<>();

			// adjacent components (not part of the main composite component)
			for (AssemblyContext assembly : delegatedComponents) {
				if (!CompositeHelper.detailContainsAssembly(detail, assembly)) {
					adjacentAssemblies.add(CollectionHelper.createAssemblyContextDetail(assembly));
				}
			}

			// delegated components
			if (delegatedComponents.size() != 0) {
				handler.attackAssemblyContext(CompositeHelper.createDetails(detail, delegatedComponents), this.changes,
						detail, getAttacker());
				for (AssemblyContextDetail element : CompositeHelper.createDetails(detail, delegatedComponents)) {
					var listServices = CollectionHelper.getProvidedRestrictions(element).stream()
							.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
					handleSeff(this.changes, listServices, component);
				}
			}

			// adjacent components
			handler.attackAssemblyContext(adjacentAssemblies, this.changes, detail, getAttacker());
			for (AssemblyContextDetail element : adjacentAssemblies) {
				var listServices = CollectionHelper.getProvidedRestrictions(element).stream()
						.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
				handleSeff(this.changes, listServices, component);
			}
		}
	}

	private boolean isGlobalElement(AssemblyContextDetail assemblyContext) {
		return this.modelStorage.getVulnerabilitySpecification().getVulnerabilities().stream()
				.filter(systemElement -> (systemElement.getPcmelement() != null)) //false in case of mitigation
				.filter(systemElement -> EcoreUtil.equals(systemElement.getPcmelement().getAssemblycontext(),
						assemblyContext.getCompromisedComponents().get(0)))
				.noneMatch(NonGlobalCommunication.class::isInstance);
	}

	protected abstract AssemblyContextHandler getAssemblyHandler();

	@Override
	public void calculateAssemblyContextToLinkingResourcePropagation() {
		final var listCompromisedAssemblyContexts = getCompromisedAssemblyContexts();

		for (final var detail : listCompromisedAssemblyContexts) {
			for (AssemblyContext component : detail.getCompromisedComponents()) {
				final var resource = getResourceContainer(component);
				final var reachableLinkingResources = getLinkingResource(resource).stream()
						.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
				final var handler = getLinkingHandler();
				handler.attackLinkingResource(reachableLinkingResources, this.changes, component, getAttacker());
			}
		}
	}

	protected abstract LinkingResourceHandler getLinkingHandler();
}
