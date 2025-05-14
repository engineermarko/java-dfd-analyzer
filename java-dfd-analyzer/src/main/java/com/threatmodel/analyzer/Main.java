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
