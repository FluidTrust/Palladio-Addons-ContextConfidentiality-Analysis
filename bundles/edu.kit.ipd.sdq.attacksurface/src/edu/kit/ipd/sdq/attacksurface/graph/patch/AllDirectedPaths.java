/*
 * (C) Copyright 2015-2021, by Vera-Licona Research Group and Contributors.
 *
 * JGraphT : a free Java graph-theory library
 *
 * See the CONTRIBUTORS.md file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the
 * GNU Lesser General Public License v2.1 or later
 * which is available at
 * http://www.gnu.org/licenses/old-licenses/lgpl-2.1-standalone.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR LGPL-2.1-or-later
 */
package edu.kit.ipd.sdq.attacksurface.graph.patch;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.GraphTests;
import org.jgrapht.alg.shortestpath.PathValidator;
import org.jgrapht.graph.GraphWalk;

/**
 * A Dijkstra-like algorithm to find all paths between two sets of nodes in a directed graph, with
 * options to search only simple paths and to limit the path length.
 *
 * @param <V>
 *            the graph vertex type
 * @param <E>
 *            the graph edge type
 *
 * @author Andrew Gainer-Dewar, Google LLC
 */
public class AllDirectedPaths<V, E> {
    private final Graph<V, E> graph;

    /**
     * Provides validation for the paths which will be computed. If the validator is {@code null},
     * this means that all paths are valid.
     */
    private final PathValidator<V, E> pathValidator;

    /**
     * Create a new instance.
     *
     * @param graph
     *            the input graph
     * @throws IllegalArgumentException
     *             if the graph is not directed
     */
    public AllDirectedPaths(final Graph<V, E> graph) {
        this(graph, null);
    }

    /**
     * Create a new instance with given {@code pathValidator}.
     *
     * If non-{@code null}, the {@code pathValidator} will be used while searching for paths,
     * validating the addition of any edge to a partial path. Zero-length paths will therefore not
     * be subject to {@code pathValidator}; length-1 paths will.
     *
     * @param graph
     *            the input graph
     * @param pathValidator
     *            validator for computed paths; may be null
     * @throws IllegalArgumentException
     *             if the graph is not directed
     */
    public AllDirectedPaths(final Graph<V, E> graph, final PathValidator<V, E> pathValidator) {
        this.graph = GraphTests.requireDirected(graph);
        this.pathValidator = pathValidator;
    }

    /**
     * Calculate (and return) all paths from the source vertex to the target vertex.
     *
     * @param sourceVertex
     *            the source vertex
     * @param targetVertex
     *            the target vertex
     * @param simplePathsOnly
     *            if true, only search simple (non-self-intersecting) paths
     * @param maxPathLength
     *            maximum number of edges to allow in a path (if null, all paths are considered,
     *            which may be very slow due to potentially huge output)
     * @return all paths from the source vertex to the target vertex
     */
    public List<GraphPath<V, E>> getAllPaths(final V sourceVertex, final V targetVertex, final boolean simplePathsOnly,
            final Integer maxPathLength) {
        return this.getAllPaths(Collections.singleton(sourceVertex), Collections.singleton(targetVertex),
                simplePathsOnly, maxPathLength);
    }

    /**
     * Calculate (and return) all paths from the source vertices to the target vertices.
     *
     * @param sourceVertices
     *            the source vertices
     * @param targetVertices
     *            the target vertices
     * @param simplePathsOnly
     *            if true, only search simple (non-self-intersecting) paths
     * @param maxPathLength
     *            maximum number of edges to allow in a path (if null, all paths are considered,
     *            which may be very slow due to potentially huge output)
     *
     * @return list of all paths from the sources to the targets containing no more than
     *         maxPathLength edges
     */
    public List<GraphPath<V, E>> getAllPaths(final Set<V> sourceVertices, final Set<V> targetVertices,
            final boolean simplePathsOnly, final Integer maxPathLength) {
        if ((maxPathLength != null) && (maxPathLength < 0)) {
            throw new IllegalArgumentException("maxPathLength must be non-negative if defined");
        }

        if (!simplePathsOnly && (maxPathLength == null)) {
            throw new IllegalArgumentException(
                    "If search is not restricted to simple paths, a maximum path length must be set to avoid infinite cycles");
        }

        if ((sourceVertices.isEmpty()) || (targetVertices.isEmpty())) {
            return Collections.emptyList();
        }

        // Decorate the edges with the minimum path lengths through them
        final var edgeMinDistancesFromTargets = this.edgeMinDistancesBackwards(targetVertices, maxPathLength);

        // Generate all the paths

        return this.generatePaths(sourceVertices, targetVertices, simplePathsOnly, maxPathLength,
                edgeMinDistancesFromTargets);
    }

    /**
     * Compute the minimum number of edges in a path to the targets through each edge, so long as it
     * is not greater than a bound.
     *
     * @param targetVertices
     *            the target vertices
     * @param maxPathLength
     *            maximum number of edges to allow in a path (if null, all edges will be considered,
     *            which may be expensive)
     *
     * @return the minimum number of edges in a path from each edge to the targets, encoded in a Map
     */
    private Map<E, Integer> edgeMinDistancesBackwards(final Set<V> targetVertices, final Integer maxPathLength) {
        /*
         * We walk backwards through the network from the target vertices, marking edges and
         * vertices with their minimum distances as we go.
         */
        final Map<E, Integer> edgeMinDistances = new HashMap<>();
        final Map<V, Integer> vertexMinDistances = new HashMap<>();
        final Queue<V> verticesToProcess = new ArrayDeque<>();

        // Input sanity checking
        if (maxPathLength != null) {
            if (maxPathLength < 0) {
                throw new IllegalArgumentException("maxPathLength must be non-negative if defined");
            }
            if (maxPathLength == 0) {
                return edgeMinDistances;
            }
        }

        // Bootstrap the process with the target vertices
        for (final V target : targetVertices) {
            vertexMinDistances.put(target, 0);
            verticesToProcess.add(target);
        }

        // Work through the node queue. When it's empty, we're done!
        for (V vertex; (vertex = verticesToProcess.poll()) != null;) {
            assert vertexMinDistances.containsKey(vertex);

            final Integer childDistance = vertexMinDistances.get(vertex) + 1;

            // Check whether the incoming edges of this node are correctly
            // decorated
            for (final E edge : this.graph.incomingEdgesOf(vertex)) {
                // Mark the edge if needed
                if (!edgeMinDistances.containsKey(edge) || (edgeMinDistances.get(edge) > childDistance)) {
                    edgeMinDistances.put(edge, childDistance);
                }

                // Mark the edge's source vertex if needed
                final var edgeSource = this.graph.getEdgeSource(edge);
                if (!vertexMinDistances.containsKey(edgeSource)
                        || (vertexMinDistances.get(edgeSource) > childDistance)) {
                    vertexMinDistances.put(edgeSource, childDistance);

                    if ((maxPathLength == null) || (childDistance < maxPathLength)) {
                        verticesToProcess.add(edgeSource);
                    }
                }
            }
        }

        assert verticesToProcess.isEmpty();
        return edgeMinDistances;
    }

    /**
     * Generate all paths from the sources to the targets, using pre-computed minimum distances.
     *
     * @param sourceVertices
     *            the source vertices
     * @param targetVertices
     *            the target vertices
     * @param maxPathLength
     *            maximum number of edges to allow in a path
     * @param simplePathsOnly
     *            if true, only search simple (non-self-intersecting) paths (if null, all edges will
     *            be considered, which may be expensive)
     * @param edgeMinDistancesFromTargets
     *            the minimum number of edges in a path to a target through each edge, as computed
     *            by {@code
     * edgeMinDistancesBackwards}.
     *
     * @return a List of all GraphPaths from the sources to the targets satisfying the given
     *         constraints
     */
    private List<GraphPath<V, E>> generatePaths(final Set<V> sourceVertices, final Set<V> targetVertices,
            final boolean simplePathsOnly, final Integer maxPathLength,
            final Map<E, Integer> edgeMinDistancesFromTargets) {
        /*
         * We walk forwards through the network from the source vertices, exploring all outgoing
         * edges whose minimum distances is small enough.
         */
        final List<GraphPath<V, E>> completePaths = new ArrayList<>();
        final Deque<List<E>> incompletePaths = new LinkedList<>();

        // Input sanity checking
        if (maxPathLength != null && maxPathLength < 0) {
            throw new IllegalArgumentException("maxPathLength must be non-negative if defined");
        }

        // Bootstrap the search with the source vertices
        for (final V source : sourceVertices) {
            if (targetVertices.contains(source)) {
                // pathValidator intentionally not invoked here
                completePaths.add(GraphWalk.singletonWalk(this.graph, source, 0d));
            }

            if (maxPathLength != null && maxPathLength == 0) {
                continue;
            }

            for (final E edge : this.graph.outgoingEdgesOf(source)) {
                assert this.graph.getEdgeSource(edge)
                    .equals(source);

                if (this.pathValidator == null
                        || this.pathValidator.isValidPath(GraphWalk.emptyWalk(this.graph), edge)) {
                    if (targetVertices.contains(this.graph.getEdgeTarget(edge))) {
                        completePaths.add(this.makePath(Collections.singletonList(edge)));
                        return completePaths;
                    }

                    if (edgeMinDistancesFromTargets.containsKey(edge) && (maxPathLength == null || maxPathLength > 1)) {
                        final List<E> path = Collections.singletonList(edge);
                        incompletePaths.add(path);
                    }
                }
            }
        }

        if (maxPathLength != null && maxPathLength == 0) {
            return completePaths;
        }

        // Walk through the queue of incomplete paths
        for (List<E> incompletePath; (incompletePath = incompletePaths.poll()) != null;) {
            final Integer lengthSoFar = incompletePath.size();
            assert (maxPathLength == null) || (lengthSoFar < maxPathLength);

            final var leafEdge = incompletePath.get(lengthSoFar - 1);
            final var leafNode = this.graph.getEdgeTarget(leafEdge);

            final Set<V> pathVertices = new HashSet<>();
            for (final E pathEdge : incompletePath) {
                pathVertices.add(this.graph.getEdgeSource(pathEdge));
                pathVertices.add(this.graph.getEdgeTarget(pathEdge));
            }

            for (final E outEdge : this.graph.outgoingEdgesOf(leafNode)) {
                // Proceed if the outgoing edge is marked and the mark
                // is sufficiently small
                if (edgeMinDistancesFromTargets.containsKey(outEdge) && ((maxPathLength == null)
                        || ((edgeMinDistancesFromTargets.get(outEdge) + lengthSoFar) <= maxPathLength))) {
                    final List<E> newPath = new ArrayList<>(incompletePath);
                    newPath.add(outEdge);

                    // If requested, make sure this path isn't self-intersecting
                    // If requested, validate the path
                    if ((simplePathsOnly && pathVertices.contains(this.graph.getEdgeTarget(outEdge))) || (this.pathValidator != null
                            && !this.pathValidator.isValidPath(this.makePath(incompletePath), outEdge))) {
                        continue;
                    }

                    // If this path reaches a target, add it to completePaths
                    if (targetVertices.contains(this.graph.getEdgeTarget(outEdge))) {
                        final var completePath = this.makePath(newPath);
                        assert sourceVertices.contains(completePath.getStartVertex());
                        assert targetVertices.contains(completePath.getEndVertex());
                        assert (maxPathLength == null) || (completePath.getLength() <= maxPathLength);
                        completePaths.add(completePath);
                        return completePaths;
                    }

                    // If this path is short enough, consider further
                    // extensions of it
                    if ((maxPathLength == null) || (newPath.size() < maxPathLength)) {
                        incompletePaths.addFirst(newPath); // We use
                                                           // incompletePaths in
                                                           // FIFO mode to avoid
                                                           // memory blowup
                    }
                }
            }
        }

        assert incompletePaths.isEmpty();
        return completePaths;
    }

    /**
     * Transform an ordered list of edges into a GraphPath.
     *
     * The weight of the generated GraphPath is set to the sum of the weights of the edges.
     *
     * @param edges
     *            the edges
     *
     * @return the corresponding GraphPath
     */
    private GraphPath<V, E> makePath(final List<E> edges) {
        final var source = this.graph.getEdgeSource(edges.get(0));
        final var target = this.graph.getEdgeTarget(edges.get(edges.size() - 1));
        final var weight = edges.stream()
            .mapToDouble(edge -> this.graph.getEdgeWeight(edge))
            .sum();
        return new GraphWalk<>(this.graph, source, target, edges, weight);
    }
}
