package edu.kit.kastel.sdq.kamp4attack.graph.impl.output;

import java.util.stream.Collectors;

import com.google.common.graph.MutableValueGraph;

public class DotCreation implements OutputFormat {

    @Override
    public String createOutputFormat(final MutableValueGraph<String, String> graph) {

        var body = graph.edges().stream().map(edge -> String.format("\"%s\" -> \"%s\" [ label = \"%s\"]", edge.nodeU(),
                edge.nodeV(), graph.edgeValueOrDefault(edge, ""))).collect(Collectors.joining("\n"));

        return String.join("\n", "digraph g {", body, "}");
    }

}
