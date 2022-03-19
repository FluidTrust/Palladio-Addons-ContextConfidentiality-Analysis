package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.ProvidedDelegationConnector;
import org.palladiosimulator.pcm.repository.CompositeComponent;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.system.System;

import com.google.common.collect.Iterables;

/**
 * Helper class for handling composite components
 * 
 * @author Patrick Spiesberger
 *
 */
public class CompositeHelper {

	/**
	 * checks if given component is a CompositeComponent
	 */
	public static boolean isCompositeComponent(AssemblyContext context) {
		if (context.getEncapsulatedComponent__AssemblyContext() instanceof CompositeComponent) {
			return true;
		}
		return false; // BasicComponent
	}

	/*
	 * Returns all connected components. Caution: No components within a composite
	 * component are returned. The getDeligatedCompositeComponents method is used
	 * for this
	 */
	public static List<AssemblyContext> getAdjacentComponents(final AssemblyContext component, System system) {
		final var targetConnectors = getTargetedConnectors(component, system);

		final var targetComponents = targetConnectors.stream()
				.map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
				.filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());

		targetComponents
				.addAll(targetConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
						.filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList()));
		return targetComponents;
	}

	public static List<AssemblyConnector> getTargetedConnectors(final AssemblyContext component, final System system) {
		return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
				.map(AssemblyConnector.class::cast)
				.filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
						|| EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
				.collect(Collectors.toList());
	}

	/**
	 * This method calculates all connections to delegated components as long as
	 * they are in a CompositeComponent. This means that a check is made whether the
	 * first (and by notation in the case of a BasicComponent) is a compound
	 * component and then for the last element of the list the connections are
	 * returned
	 * 
	 * @param component : component of type basic oder composite component
	 * @param system    : (sub)system to check
	 * @return : list of all connectors that have a connection to the last component
	 *         of the AssemblyContextDetail
	 */
	private static List<ProvidedDelegationConnector> getDelicatedConnectors(final AssemblyContextDetail component,
			final System system) {
		if (CompositeHelper.isCompositeComponent(component.getCompromisedComponents().get(0))
				|| component.getCompromisedComponents().size() > 1) { // component is subcomponent
			return system.getConnectors__ComposedStructure().stream()
					.filter(ProvidedDelegationConnector.class::isInstance).map(ProvidedDelegationConnector.class::cast)
					.filter(e -> EcoreUtil.equals(e.getAssemblyContext_ProvidedDelegationConnector(),
							Iterables.getLast(component.getCompromisedComponents())))
					.collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/*
	 * Returns all delegated components. Caution: the returned subcomponents are
	 * part of the main component. The getAdjacentComponents method is used for
	 * adjacent components, which are not part of the composite component
	 */
	public static List<AssemblyContext> getDelegatedCompositeComponents(final AssemblyContextDetail component,
			System system) {
		final var targetConnectors = getDelicatedConnectors(component, system);

		List<AssemblyContext> assemblies = new LinkedList<>();
		for (ProvidedDelegationConnector connector : targetConnectors) {

			var innerRole = connector.getInnerProvidedRole_ProvidedDelegationConnector()
					.getProvidedInterface__OperationProvidedRole();
			var outerRole = connector.getOuterProvidedRole_ProvidedDelegationConnector()
					.getProvidedInterface__OperationProvidedRole();

			var element = Iterables.getLast(component.getCompromisedComponents())
					.getEncapsulatedComponent__AssemblyContext();

			var interfacesList = element.getProvidedRoles_InterfaceProvidingEntity().stream()
					.filter(OperationProvidedRole.class::isInstance).map(OperationProvidedRole.class::cast)
					.map(OperationProvidedRole::getProvidedInterface__OperationProvidedRole)
					.collect(Collectors.toList());

			if (interfacesList.contains(innerRole)) {
				assemblies.add(Iterables.getLast(component.getCompromisedComponents()));
			} else if (interfacesList.contains(outerRole)) {
				assemblies.add(Iterables.getLast(component.getCompromisedComponents()));
			}
		}
		return assemblies;
	}

	public static boolean detailContainsAssembly(AssemblyContextDetail detail, AssemblyContext context) {
		// Start at second element, since the first element is the component itself
		for (int i = 1; i < detail.getCompromisedComponents().size(); i++) {
			if (EcoreUtil.equals(detail.getCompromisedComponents().get(i), context)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method gets an AssemblyContextDetail and a list of reachable components,
	 * and returns a list of AssemblyContextDetails that have one of those reachable
	 * components as the last element.
	 * 
	 * @param detail           : previously compromised AssemblyContextDetail
	 * @param targetComponents : List of reachable components from the last
	 *                         compromised element of the AssemblyContextDetails
	 * @return e.g: D is detail and [a,b,c] targetComponents -> [[D|a], [D|b],
	 *         [D|c]]
	 */
	public static List<AssemblyContextDetail> createDetails(AssemblyContextDetail detail,
			List<AssemblyContext> targetComponents) {
		List<AssemblyContextDetail> detailsToAttack = new LinkedList<>();
		for (AssemblyContext assembly : targetComponents) {
			AssemblyContextDetail assemblyDetail = AttackerFactory.eINSTANCE.createAssemblyContextDetail();
			assemblyDetail.getCompromisedComponents().addAll(detail.getCompromisedComponents());
			assemblyDetail.getCompromisedComponents().add(assembly);
			assemblyDetail.setEntityName(detail.getEntityName());
			assemblyDetail.setId(detail.getId());
			detailsToAttack.add(assemblyDetail);
		}
		return detailsToAttack;
	}

}
