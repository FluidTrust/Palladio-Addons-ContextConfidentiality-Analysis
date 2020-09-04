package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants;
/**
 * PartitionConstants of the PCM Attacker Analysis Launcher
 * @author majuwa
 * @author Mirko Sowa
 *
 */
public enum Constants {
    //FIXME convert to String constants
	NAME("Attacker Analysis Modelling Launcher"),
	BUTTON_BROWSE_TEXT("Browse..."),
	BUTTON_DIR_BROWSE_TEXT("Working Directory..."),
	ANALYSIS_TYPE_LABEL("Select Analysis Type"),
	PROLOG_INTERPRETER_LABEL("Select PROLOG Interpreter"),
	REPOSITORY_MODEL_LABEL("Select Repository Model"),
	ALLOCATION_MODEL_LABEL("Select Allocation Model"),
	MODIFIACTION_MODEL_LABEL("Select Modifiaction Model"),
	CONTEXT_MODEL_LABEL("Select Context Model"),
	DATA_MODEL_LABEL("Select Data Model"),
	ADVERSARY_MODEL_LABEL("Select Attacker Model"),
	USAGE_MODEL_LABEL("Select Usage Model"),
	CONSOLE_ID("pcm.dataprocessing.context.analysis.launcher.console"),
	DEFAULT_CONFIG_VALUE("default");
	

	private final String attr;

	Constants(String attr) {
		this.attr = attr;
	}

	public String getConstant() {
		return attr;
	}
}
