#!/bin/bash

echo "=== Java DFD Analyzer - Setup ==="
echo "This script will set up the Java DFD Analyzer project."
echo ""

# Run the project setup script
./java-dfd-analyzer.sh

# Set up source files
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer

# Main class
cat > java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/Main.java << 'JAVA_EOF'
package com.threatmodel.analyzer;

import java.nio.file.Path;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.threatmodel.analyzer.core.ProjectAnalyzer;
import com.threatmodel.analyzer.model.AnalysisResult;
import com.threatmodel.analyzer.output.DFDGenerator;
import com.threatmodel.analyzer.output.OutputGenerator;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "java-dfd-analyzer", 
         mixinStandardHelpOptions = true, 
         version = "Java DFD Analyzer 1.0",
         description = "Analyzes Java projects to create data flow diagrams for threat modeling")
public class Main implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    @Option(names = {"-p", "--path"}, description = "Path to Java project root directory", required = true)
    private Path projectPath;

    @Option(names = {"-o", "--output"}, description = "Output directory for generated files", required = true)
    private Path outputPath;

    @Option(names = {"-f", "--format"}, description = "Output format (json, csv, markdown, html)", defaultValue = "markdown")
    private String outputFormat;

    @Option(names = {"--generate-dfd"}, description = "Generate Data Flow Diagram", defaultValue = "true")
    private boolean generateDfd;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        try {
            logger.info("Starting analysis of Java project at: {}", projectPath);
            
            // Analyze the project
            ProjectAnalyzer analyzer = new ProjectAnalyzer(projectPath);
            AnalysisResult result = analyzer.analyze();
            
            // Generate output
            OutputGenerator outputGenerator = new OutputGenerator(result, outputPath, outputFormat);
            outputGenerator.generate();
            
            // Generate DFD if requested
            if (generateDfd) {
                DFDGenerator dfdGenerator = new DFDGenerator(result, outputPath);
                dfdGenerator.generate();
            }
            
            logger.info("Analysis completed successfully. Results saved to: {}", outputPath);
            return 0;
        } catch (Exception e) {
            logger.error("Error during analysis", e);
            return 1;
        }
    }
}
JAVA_EOF

# Create model classes
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/model

# AnalysisResult.java
cat > java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/model/AnalysisResult.java << 'JAVA_EOF'
package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the complete analysis result of a Java project
 */
public class AnalysisResult {
    private List<DataStructure> dataStructures = new ArrayList<>();
    private List<DataFlow> dataFlows = new ArrayList<>();
    private List<ExternalEntity> externalEntities = new ArrayList<>();
    private List<Process> processes = new ArrayList<>();
    private List<DataStore> dataStores = new ArrayList<>();
    
    // Project metadata
    private String projectName;
    private String projectDescription;
    private Map<String, String> projectMetadata = new HashMap<>();

    public List<DataStructure> getDataStructures() {
        return dataStructures;
    }

    public void addDataStructure(DataStructure dataStructure) {
        this.dataStructures.add(dataStructure);
    }

    public List<DataFlow> getDataFlows() {
        return dataFlows;
    }

    public void addDataFlow(DataFlow dataFlow) {
        this.dataFlows.add(dataFlow);
    }

    public List<ExternalEntity> getExternalEntities() {
        return externalEntities;
    }

    public void addExternalEntity(ExternalEntity externalEntity) {
        this.externalEntities.add(externalEntity);
    }

    public List<Process> getProcesses() {
        return processes;
    }

    public void addProcess(Process process) {
        this.processes.add(process);
    }

    public List<DataStore> getDataStores() {
        return dataStores;
    }

    public void addDataStore(DataStore dataStore) {
        this.dataStores.add(dataStore);
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectDescription() {
        return projectDescription;
    }

    public void setProjectDescription(String projectDescription) {
        this.projectDescription = projectDescription;
    }

    public Map<String, String> getProjectMetadata() {
        return projectMetadata;
    }

    public void addProjectMetadata(String key, String value) {
        this.projectMetadata.put(key, value);
    }
    
    /**
     * Gets a summary of the analysis results
     */
    public String getSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Project Analysis Summary for ").append(projectName).append("\n");
        summary.append("================================\n\n");
        
        summary.append("Data Structures: ").append(dataStructures.size()).append("\n");
        summary.append("Data Flows: ").append(dataFlows.size()).append("\n");
        summary.append("External Entities: ").append(externalEntities.size()).append("\n");
        summary.append("Processes: ").append(processes.size()).append("\n");
        summary.append("Data Stores: ").append(dataStores.size()).append("\n\n");
        
        return summary.toString();
    }
}
JAVA_EOF
