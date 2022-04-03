package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.common.util.BasicEList;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.ComposedStructure;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.core.composition.ProvidedDelegationConnector;
import org.palladiosimulator.pcm.core.composition.RequiredDelegationConnector;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.OperationInterface;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.repository.OperationRequiredRole;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;

/**
 * This class was copied from Palladio-Analyzer-Solver and the bundle org.palladiosimulator.solver
 * https://github.com/PalladioSimulator/Palladio-Analyzer-Solver/tree/master/bundles/org.palladiosimulator.solver/src/org/palladiosimulator/solver/transformations
 * This was done to avoid a dependency on the solver package
 *
 * This class provides auxiliary functionality factored out from the ContextWrapper for examining
 * PCM instances.
 *
 * TODO: continue the outsourcing to separate context-independent tasks from the ContextWrapper
 * class!
 *
 * @author brosch, majuwa
 *
 */
public class PCMInstanceHelper {

    /**
     * Retrieves the list of nested handling AssemblyContexts for the given EntryLevelSystemCall.
     *
     * A handling AssemblyContext is one that includes the executing behavior triggered by the call.
     *
     * @param call
     *            the EntryLevelSystemCall
     * @param system
     *            the involved System instance
     * @return the list of nested handling AssemblyContexts
     */
    public static List<AssemblyContext> getHandlingAssemblyContexts(final EntryLevelSystemCall call,
            final System system) {

        // Find the top-level assembly context and
        // providing role for the call:
        AssemblyContext topLevelAssCtx = null;
        OperationProvidedRole topLevelAssCtxProvidedRole = null;
        for (final Connector conn : system.getConnectors__ComposedStructure()) {
            if (conn instanceof final ProvidedDelegationConnector pdc) {

                if (pdc.getOuterProvidedRole_ProvidedDelegationConnector().getId()
                        .equals(call.getProvidedRole_EntryLevelSystemCall().getId())) {
                    topLevelAssCtx = pdc.getAssemblyContext_ProvidedDelegationConnector();
                    topLevelAssCtxProvidedRole = pdc.getInnerProvidedRole_ProvidedDelegationConnector();
                }
            }
        }

        if (topLevelAssCtx != null) {
            return getHandlingAssemblyContexts(topLevelAssCtx, topLevelAssCtxProvidedRole,
                    new BasicEList<AssemblyContext>());
        }

        // No matching ProvidedDelegationConnector found:
        throw new IllegalArgumentException("No ProvidedDelegationConnector found in system \"" + system.getEntityName()
                + "\" that matches the EntryLevelSystemCall \"" + call.getEntityName() + "\".");
    }

    /**
     * Searches for the providing AssemblyContexts that handle the given ExternalCallAction.
     *
     * If the ExternalCallAction is a system external call, the method returns an empty list. If the
     * providing side is a nested structure of AssemblyContexts, all providing AssemblyContexts are
     * returned in a list, with the actual handling context as the last element.
     *
     * @param call
     *            the ExternallCallAction
     * @param encapsulatingContexts
     *            the list of encapsulating AssemblyContexts of the ExternalCallAction (required for
     *            its unique identification)
     * @return the list of nested handling AssemblyContexts
     */
    public static List<AssemblyContext> getHandlingAssemblyContexts(final ExternalCallAction call,
            final List<AssemblyContext> encapsulatingContexts) {

        // Copy the received list of contexts:
        final List<AssemblyContext> contexts = new ArrayList<>(encapsulatingContexts);

        // Search for an AssemblyConnector between the calling
        // AssemblyContext and the handling AssemblyContext:
        final var connector = getAssemblyConnectorForRequiredRole(call.getRole_ExternalService(),
                (OperationInterface) call.getCalledService_ExternalService().eContainer(), contexts);
        if (connector == null) {
            // If no AssemblyConnector is found, the call is a system external
            // call and has no handling AssemblyContext:
            return new ArrayList<>();
        }

        // Retrieve the set of handling assembly contexts from:
        return getHandlingAssemblyContexts(connector.getProvidingAssemblyContext_AssemblyConnector(),
                connector.getProvidedRole_AssemblyConnector(), contexts);
    }

    /**
     * Searches for an AssemblyConnector that connects the current {@link AssemblyContext} via its
     * given {@link ExternalCallAction}.
     *
     * The current AssemblyContext is the last element in the AssemblyContext list
     *
     * @param call
     *            the {@link ExternalCallAction}
     * @param encapsulatingContexts
     *            the current {@link AssemblyContext}
     * @return the AssemblyConnector, or NULL if the ExternalCallAction leads to the system boundary
     */
    public static AssemblyConnector getAssemblyConnectorForExternalCall(final ExternalCallAction call,
            final List<AssemblyContext> encapsulatingContexts) {
        final var contexts = new ArrayList<>(encapsulatingContexts);
        return getAssemblyConnectorForRequiredRole(call.getRole_ExternalService(),
                (OperationInterface) call.getCalledService_ExternalService().eContainer(), contexts);
    }

    /**
     * Searches for an AssemblyConnector that connects the current AssemblyContext via its given
     * requiredRole to its providing counterpart.
     *
     * The current AssemblyContext is the last element of the given list of nested contexts. The
     * method traverses any RequiredDelegationConnectors that lie between the AssemblyContext and
     * its AssemblyConnector. If the role is connected to the system boundary, the method returns
     * NULL. During the method, the list of nestedContexts is adapted to the current search level.
     * If a connector is found, the resulting list reflects the encapsulating contexts of the
     * connector.
     *
     * @param requiredRole
     *            the RequiredRole to match
     * @param requiredInterfaceId
     *            the Interface to match
     * @return the AssemblyConnector, or NULL, if the required role leads to the system boundary
     */
    private static AssemblyConnector getAssemblyConnectorForRequiredRole(final OperationRequiredRole requiredRole,
            final OperationInterface requiredInterface, final List<AssemblyContext> nestedContexts) {

        // Navigate upwards the stack of parent AssemblyContexts
        // (starting from the current AssemblyContext):
        var currentRequiredRole = requiredRole;
        AssemblyContext currentContext = null;
        while (!nestedContexts.isEmpty()) {

            // Examine the innermost context of the list:
            currentContext = nestedContexts.get(nestedContexts.size() - 1);
            nestedContexts.remove(currentContext);

            // Check if the searched AssemblyConnector is directly
            // connected to the currently examined context:
            final var matchingAssConn = getAssemblyConnectorForRequiringAssemblyContext(currentRequiredRole,
                    requiredInterface, currentContext);
            if (matchingAssConn != null) {
                return matchingAssConn;
            }

            // As no AssemblyConnector is directly connected, we
            // have to look for a RequiredDelegationConnector
            // instead and repeat the search for the next higher
            // AssemblyContext and its corresponding
            // OperationRequiredRole:
            final var matchingDeleConn = getDelegationConnectorForRequiringAssemblyContext(currentRequiredRole,
                    requiredInterface, currentContext);
            if (matchingDeleConn == null) {
                // Error handling:
                throw new IllegalArgumentException(
                        "Neither an AssemblyConnector nor a RequiredDelegationConnector could be found "
                                + "connected to the OperationRequiredRole \"" + currentRequiredRole.getEntityName()
                                + "\" for the OperationInterface \"" + requiredInterface.getEntityName()
                                + "\" of the AssemblyContext \"" + currentContext.getEntityName() + "\".");
            }
            currentRequiredRole = matchingDeleConn.getOuterRequiredRole_RequiredDelegationConnector();
        }

        // No AssemblyContext found:
        return null;
    }

    /**
     * Searches for an AssemblyConnector that connects a given requiringAssemblyContext via its
     * requiredRole to its providing counterpart.
     *
     * Notice that the requiredRole of the requiringAssemblyContext could also be associated to a
     * RequiredDelegationConnector instead of an AssemblyConnector. In this case, NULL is returned.
     *
     * @param requiredRole
     *            the RequiredRole to match
     * @param requiredInterface
     *            the Interface to match
     * @param requiringContext
     *            the AssemblyContext to match
     * @return the matching AssemblyConnector within the parent ComposedStructure
     */
    private static AssemblyConnector getAssemblyConnectorForRequiringAssemblyContext(
            final OperationRequiredRole requiredRole, final OperationInterface requiredInterface,
            final AssemblyContext requiringContext) {

        // Retrieve the list of connectors within the parent
        // ComposedStructure:
        final var connList = requiringContext.getParentStructure__AssemblyContext().getConnectors__ComposedStructure();

        // Check for each AssemblyConnector in the list if it fulfills
        // the requirements:
        for (final Connector conn : connList) {
            if (conn instanceof final AssemblyConnector assConn) {
                if (assConn.getRequiringAssemblyContext_AssemblyConnector().getId().equals(requiringContext.getId())
                        && assConn.getRequiredRole_AssemblyConnector().getRequiredInterface__OperationRequiredRole()
                                .getId().equals(requiredInterface.getId())
                        && assConn.getRequiredRole_AssemblyConnector().getId().equals(requiredRole.getId())) {
                    return assConn;
                }
            }
        }

        // No AssmblyConnector found:
        return null;
    }

    /**
     * Searches for a RequiredDelegationConnector that connects a given requiring AssemblyContext
     * via its requiredRole to an encapsulating ComposedStructure.
     *
     * Notice that the requiredRole of the requiring AssemblyContext could also be associated to an
     * AssemblyConnector instead of a RequiredDelegationConnector. In this case, NULL is returned.
     *
     * @param requiredRole
     *            the RequiredRole to match
     * @param requiredInterface
     *            the Interface to match
     * @param requiringContext
     *            the AssemblyContext to match
     * @return the matching RequiredDelegationConnector within the parent ComposedStructure
     */
    private static RequiredDelegationConnector getDelegationConnectorForRequiringAssemblyContext(
            final OperationRequiredRole requiredRole, final OperationInterface requiredInterface,
            final AssemblyContext requiringContext) {

        // Retrieve the list of connectors within the parent
        // ComposedStructure:
        final var connList = requiringContext.getParentStructure__AssemblyContext().getConnectors__ComposedStructure();

        // Check for each RequiredDelegationConnector in the list if it fulfills
        // the requirements:
        for (final Connector conn : connList) {
            if (conn instanceof final RequiredDelegationConnector dc) {
                if (dc.getAssemblyContext_RequiredDelegationConnector().getId().equals(requiringContext.getId())
                        && dc.getInnerRequiredRole_RequiredDelegationConnector()
                                .getRequiredInterface__OperationRequiredRole().getId().equals(requiredInterface.getId())
                        && dc.getInnerRequiredRole_RequiredDelegationConnector().getId().equals(requiredRole.getId())) {
                    return dc;
                }
            }
        }

        // No RequiredDelegationConnector found:
        return null;
    }

    /**
     * Extends a given list of AssemblyContexts with a given top-level AssemblyContext and all
     * nested ones, according to a given top-level OperationProvidedRole.
     *
     * @param topLevelContexts
     *            the top-level AssemblyContext
     * @param topLevelProvidedRole
     *            the top-level OperationProvidedRole, which is assumed to belong to the component
     *            encapsulated by the top-level AssemblyContext.
     * @param existingContexts
     *            the existing list of AssemblyContexts
     * @return the extended AssemblyContext list
     */
    private static List<AssemblyContext> getHandlingAssemblyContexts(final AssemblyContext topLevelContexts,
            final OperationProvidedRole topLevelProvidedRole, final List<AssemblyContext> existingContexts) {

        // In any case, the top-level AssemblyContext itself
        // will be added to the list:
        existingContexts.add(topLevelContexts);

        // Retrieve the encapsulated top-level component:
        final var rc = topLevelContexts.getEncapsulatedComponent__AssemblyContext();

        // Check for the type of the top-level component:
        if (rc instanceof BasicComponent) {

            // Case 1: We already have a basic component. Hence,
            // there are no more nested AssemblyContexts to add:
            return existingContexts;

        } else if (rc instanceof final ComposedStructure cs) {

            // Case 2: We have a composed structure. Hence, a
            // ProvidedDelegationConnector will lead us to a
            // nested AssemblyContext:
            for (final Connector conn : cs.getConnectors__ComposedStructure()) {
                if (conn instanceof final ProvidedDelegationConnector pdc) {
                    if (pdc.getOuterProvidedRole_ProvidedDelegationConnector().getId()
                            .equals(topLevelProvidedRole.getId())) {

                        // We have found a ProvidedDelegationConnector that
                        // delegates from a nested AssemblyContext to the
                        // top-level ProvidedRole. Now, we recursively
                        // continue with the nested AssemblyContext:
                        final var nestedAssCtx = pdc.getAssemblyContext_ProvidedDelegationConnector();
                        final var nestedProvidedRole = pdc.getInnerProvidedRole_ProvidedDelegationConnector();
                        return getHandlingAssemblyContexts(nestedAssCtx, nestedProvidedRole, existingContexts);
                    }
                }
            }

            // Error handling in case no matching ProvidedDelegationConnector
            // has been found:
            throw new IllegalArgumentException("No ProvidedDelegationConnector found in ComposedStructure \""
                    + cs.getEntityName() + "\" that matches the OperationProvidedRole \""
                    + topLevelProvidedRole.getEntityName() + "\".");
        }

        // Error handling in case an unknown component type is encountered:
        throw new IllegalArgumentException("Unknown component type \"" + rc.eClass().getName()
                + "\" encapsulated by AssemblyContext \"" + topLevelContexts.getEntityName() + "\"");
    }
}
