package edu.kit.kastel.sdq.kamp4attack.graph.impl.output;

import com.google.common.graph.MutableValueGraph;

public interface OutputFormat {

    String createOutputFormat(MutableValueGraph<String, String> graph);

}
