package com.threatmodel.analyzer.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatmodel.analyzer.model.AnalysisResult;

/**
 * Class for generating output files from analysis results
 */
public class OutputGenerator {
    private static final Logger logger = LoggerFactory.getLogger(OutputGenerator.class);
    
    private final AnalysisResult result;
    private final Path outputPath;
    private final String format;
    
    public OutputGenerator(AnalysisResult result, Path outputPath, String format) {
        this.result = result;
        this.outputPath = outputPath;
        this.format = format.toLowerCase();
    }
    
    /**
     * Generates output files in the specified format
     */
    public void generate() throws IOException {
        // Create output directory if it doesn't exist
        if (!Files.exists(outputPath)) {
            Files.createDirectories(outputPath);
        }
        
        // Generate appropriate format
        switch (format) {
            case "json":
                generateJson();
                break;
            case "csv":
                generateCsv();
                break;
            case "html":
                generateHtml();
                break;
            case "markdown":
            default:
                generateMarkdown();
                break;
        }
        
        logger.info("Output generated in {} format at: {}", format, outputPath);
    }
    
    /**
     * Generates JSON output
     */
    private void generateJson() throws IOException {
        Path jsonFile = outputPath.resolve("analysis-result.json");
        
        ObjectMapper mapper = new ObjectMapper();
        mapper.writerWithDefaultPrettyPrinter().writeValue(jsonFile.toFile(), result);
        
        logger.info("JSON output written to: {}", jsonFile);
    }
    
    /**
     * Generates CSV output
     */
    private void generateCsv() throws IOException {
        Path dataStructuresFile = outputPath.resolve("data-structures.csv");
        Path dataFlowsFile = outputPath.resolve("data-flows.csv");
        Path externalEntitiesFile = outputPath.resolve("external-entities.csv");
        Path processesFile = outputPath.resolve("processes.csv");
        Path dataStoresFile = outputPath.resolve("data-stores.csv");
        
        // Generate CSV for data structures
        StringBuilder sbStructures = new StringBuilder();
        sbStructures.append("Name,Type,Description,External,Source File,Fields\n");
        
        for (com.threatmodel.analyzer.model.DataStructure structure : result.getDataStructures()) {
            sbStructures.append(escapeCsv(structure.getName())).append(",");
            sbStructures.append(escapeCsv(structure.getType().toString())).append(",");
            sbStructures.append(escapeCsv(structure.getDescription())).append(",");
            sbStructures.append(structure.isExternal()).append(",");
            sbStructures.append(escapeCsv(structure.getSourceFilePath())).append(",");
            
            StringBuilder fields = new StringBuilder();
            for (com.threatmodel.analyzer.model.DataField field : structure.getFields()) {
                if (fields.length() > 0) {
                    fields.append("; ");
                }
                fields.append(field.getName()).append(": ").append(field.getType());
                if (field.isSensitive()) {
                    fields.append(" [SENSITIVE]");
                }
            }
            sbStructures.append(escapeCsv(fields.toString())).append("\n");
        }
        
        Files.writeString(dataStructuresFile, sbStructures.toString());
        
        // Generate CSV for data flows
        StringBuilder sbFlows = new StringBuilder();
        sbFlows.append("Source,Destination,Data Structure,Type,Protocol,External,Description\n");
        
        for (com.threatmodel.analyzer.model.DataFlow flow : result.getDataFlows()) {
            sbFlows.append(escapeCsv(flow.getSourceId())).append(",");
            sbFlows.append(escapeCsv(flow.getDestinationId())).append(",");
            sbFlows.append(escapeCsv(flow.getDataStructureId())).append(",");
            sbFlows.append(escapeCsv(flow.getType().toString())).append(",");
            sbFlows.append(escapeCsv(flow.getProtocol())).append(",");
            sbFlows.append(flow.isExternal()).append(",");
            sbFlows.append(escapeCsv(flow.getDescription())).append("\n");
        }
        
        Files.writeString(dataFlowsFile, sbFlows.toString());
        
        // Generate CSV for external entities
        StringBuilder sbEntities = new StringBuilder();
        sbEntities.append("Name,Type,Description,Protocols\n");
        
        for (com.threatmodel.analyzer.model.ExternalEntity entity : result.getExternalEntities()) {
            sbEntities.append(escapeCsv(entity.getName())).append(",");
            sbEntities.append(escapeCsv(entity.getType().toString())).append(",");
            sbEntities.append(escapeCsv(entity.getDescription())).append(",");
            
            StringBuilder protocols = new StringBuilder();
            for (String protocol : entity.getProtocols()) {
                if (protocols.length() > 0) {
                    protocols.append("; ");
                }
                protocols.append(protocol);
            }
            sbEntities.append(escapeCsv(protocols.toString())).append("\n");
        }
        
        Files.writeString(externalEntitiesFile, sbEntities.toString());
        
        // Generate CSV for processes
        StringBuilder sbProcesses = new StringBuilder();
        sbProcesses.append("ID,Name,Description,Source File,Input Data Structures,Output Data Structures\n");
        
        for (com.threatmodel.analyzer.model.Process process : result.getProcesses()) {
            sbProcesses.append(escapeCsv(process.getId())).append(",");
            sbProcesses.append(escapeCsv(process.getName())).append(",");
            sbProcesses.append(escapeCsv(process.getDescription())).append(",");
            sbProcesses.append(escapeCsv(process.getSourceFilePath())).append(",");
            
            StringBuilder inputs = new StringBuilder();
            for (String inputId : process.getInputDataStructureIds()) {
                if (inputs.length() > 0) {
                    inputs.append("; ");
                }
                inputs.append(inputId);
            }
            sbProcesses.append(escapeCsv(inputs.toString())).append(",");
            
            StringBuilder outputs = new StringBuilder();
            for (String outputId : process.getOutputDataStructureIds()) {
                if (outputs.length() > 0) {
                    outputs.append("; ");
                }
                outputs.append(outputId);
            }
            sbProcesses.append(escapeCsv(outputs.toString())).append("\n");
        }
        
        Files.writeString(processesFile, sbProcesses.toString());
        
        // Generate CSV for data stores
        StringBuilder sbStores = new StringBuilder();
        sbStores.append("ID,Name,Type,Description,Data Structures\n");
        
        for (com.threatmodel.analyzer.model.DataStore store : result.getDataStores()) {
            sbStores.append(escapeCsv(store.getId())).append(",");
            sbStores.append(escapeCsv(store.getName())).append(",");
            sbStores.append(escapeCsv(store.getType().toString())).append(",");
            sbStores.append(escapeCsv(store.getDescription())).append(",");
            
            StringBuilder structures = new StringBuilder();
            for (String structureId : store.getDataStructureIds()) {
                if (structures.length() > 0) {
                    structures.append("; ");
                }
                structures.append(structureId);
            }
            sbStores.append(escapeCsv(structures.toString())).append("\n");
        }
        
        Files.writeString(dataStoresFile, sbStores.toString());
        
        logger.info("CSV output written to: {}", outputPath);
    }
    
    /**
     * Generates HTML output
     */
    private void generateHtml() throws IOException {
        Path htmlFile = outputPath.resolve("analysis-result.html");
        
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"en\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>Data Flow Analysis - ").append(result.getProjectName()).append("</title>\n");
        html.append("    <style>\n");
        html.append("        body { font-family: Arial, sans-serif; margin: 20px; }\n");
        html.append("        h1 { color: #2c3e50; }\n");
        html.append("        h2 { color: #3498db; margin-top: 30px; }\n");
        html.append("        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n");
        html.append("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.append("        th { background-color: #f2f2f2; }\n");
        html.append("        tr:nth-child(even) { background-color: #f9f9f9; }\n");
        html.append("        .sensitive { color: red; font-weight: bold; }\n");
        html.append("        .external { color: orange; }\n");
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        
        // Header
        html.append("    <h1>Data Flow Analysis - ").append(result.getProjectName()).append("</h1>\n");
        html.append("    <p>Generated on: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>\n");
        html.append("    <p>").append(result.getProjectDescription()).append("</p>\n");
        
        // Summary
        html.append("    <h2>Summary</h2>\n");
        html.append("    <ul>\n");
        html.append("        <li>Data Structures: ").append(result.getDataStructures().size()).append("</li>\n");
        html.append("        <li>Processes: ").append(result.getProcesses().size()).append("</li>\n");
        html.append("        <li>External Entities: ").append(result.getExternalEntities().size()).append("</li>\n");
        html.append("        <li>Data Stores: ").append(result.getDataStores().size()).append("</li>\n");
        html.append("        <li>Data Flows: ").append(result.getDataFlows().size()).append("</li>\n");
        html.append("    </ul>\n");
        
        // Data Structures
        html.append("    <h2>Data Structures</h2>\n");
        html.append("    <table>\n");
        html.append("        <tr><th>Name</th><th>Type</th><th>Description</th><th>Fields</th></tr>\n");
        
        for (com.threatmodel.analyzer.model.DataStructure structure : result.getDataStructures()) {
            html.append("        <tr>\n");
            if (structure.isExternal()) {
                html.append("            <td class=\"external\">").append(structure.getName()).append(" [EXTERNAL]</td>\n");
            } else {
                html.append("            <td>").append(structure.getName()).append("</td>\n");
            }
            html.append("            <td>").append(structure.getType()).append("</td>\n");
            html.append("            <td>").append(structure.getDescription() != null ? structure.getDescription() : "").append("</td>\n");
            
            html.append("            <td><ul>\n");
            for (com.threatmodel.analyzer.model.DataField field : structure.getFields()) {
                if (field.isSensitive()) {
                    html.append("                <li class=\"sensitive\">");
                } else {
                    html.append("                <li>");
                }
                html.append(field.getName()).append(": ").append(field.getType());
                if (field.getDescription() != null && !field.getDescription().isEmpty()) {
                    html.append(" - ").append(field.getDescription());
                }
                html.append("</li>\n");
            }
            html.append("            </ul></td>\n");
            
            html.append("        </tr>\n");
        }
        
        html.append("    </table>\n");
        
        // External Entities
        html.append("    <h2>External Entities</h2>\n");
        html.append("    <table>\n");
        html.append("        <tr><th>Name</th><th>Type</th><th>Description</th><th>Protocols</th></tr>\n");
        
        for (com.threatmodel.analyzer.model.ExternalEntity entity : result.getExternalEntities()) {
            html.append("        <tr>\n");
            html.append("            <td>").append(entity.getName()).append("</td>\n");
            html.append("            <td>").append(entity.getType()).append("</td>\n");
            html.append("            <td>").append(entity.getDescription() != null ? entity.getDescription() : "").append("</td>\n");
            
            html.append("            <td><ul>\n");
            for (String protocol : entity.getProtocols()) {
                html.append("                <li>").append(protocol).append("</li>\n");
            }
            html.append("            </ul></td>\n");
            
            html.append("        </tr>\n");
        }
        
        html.append("    </table>\n");
        
        // Processes
        html.append("    <h2>Processes</h2>\n");
        html.append("    <table>\n");
        html.append("        <tr><th>Name</th><th>Description</th><th>Inputs</th><th>Outputs</th></tr>\n");
        
        for (com.threatmodel.analyzer.model.Process process : result.getProcesses()) {
            html.append("        <tr>\n");
            html.append("            <td>").append(process.getName()).append("</td>\n");
            html.append("            <td>").append(process.getDescription() != null ? process.getDescription() : "").append("</td>\n");
            
            html.append("            <td><ul>\n");
            for (String inputId : process.getInputDataStructureIds()) {
                html.append("                <li>").append(inputId).append("</li>\n");
            }
            html.append("            </ul></td>\n");
            
            html.append("            <td><ul>\n");
            for (String outputId : process.getOutputDataStructureIds()) {
                html.append("                <li>").append(outputId).append("</li>\n");
            }
            html.append("            </ul></td>\n");
            
            html.append("        </tr>\n");
        }
        
        html.append("    </table>\n");
        
        // Data Stores
        html.append("    <h2>Data Stores</h2>\n");
        html.append("    <table>\n");
        html.append("        <tr><th>Name</th><th>Type</th><th>Description</th><th>Data Structures</th></tr>\n");
        
        for (com.threatmodel.analyzer.model.DataStore store : result.getDataStores()) {
            html.append("        <tr>\n");
            html.append("            <td>").append(store.getName()).append("</td>\n");
            html.append("            <td>").append(store.getType()).append("</td>\n");
            html.append("            <td>").append(store.getDescription() != null ? store.getDescription() : "").append("</td>\n");
            
            html.append("            <td><ul>\n");
            for (String structureId : store.getDataStructureIds()) {
                html.append("                <li>").append(structureId).append("</li>\n");
            }
            html.append("            </ul></td>\n");
            
            html.append("        </tr>\n");
        }
        
        html.append("    </table>\n");
        
        // Data Flows
        html.append("    <h2>Data Flows</h2>\n");
        html.append("    <table>\n");
        html.append("        <tr><th>Source</th><th>Destination</th><th>Data Structure</th><th>Type</th><th>Protocol</th><th>Description</th></tr>\n");
        
        for (com.threatmodel.analyzer.model.DataFlow flow : result.getDataFlows()) {
            html.append("        <tr>\n");
            html.append("            <td>").append(flow.getSourceId()).append("</td>\n");
            html.append("            <td>").append(flow.getDestinationId()).append("</td>\n");
            html.append("            <td>").append(flow.getDataStructureId()).append("</td>\n");
            html.append("            <td>").append(flow.getType()).append("</td>\n");
            html.append("            <td>").append(flow.getProtocol() != null ? flow.getProtocol() : "").append("</td>\n");
            html.append("            <td>").append(flow.getDescription() != null ? flow.getDescription() : "").append("</td>\n");
            html.append("        </tr>\n");
        }
        
        html.append("    </table>\n");
        
        html.append("</body>\n");
        html.append("</html>\n");
        
        Files.writeString(htmlFile, html.toString());
        
        logger.info("HTML output written to: {}", htmlFile);
    }
    
    /**
     * Generates Markdown output
     */
    private void generateMarkdown() throws IOException {
        Path markdownFile = outputPath.resolve("analysis-result.md");
        
        StringBuilder md = new StringBuilder();
        md.append("# Data Flow Analysis - ").append(result.getProjectName()).append("\n\n");
        md.append("Generated on: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n\n");
        md.append(result.getProjectDescription()).append("\n\n");
        
        // Summary
        md.append("## Summary\n\n");
        md.append("- Data Structures: ").append(result.getDataStructures().size()).append("\n");
        md.append("- Processes: ").append(result.getProcesses().size()).append("\n");
        md.append("- External Entities: ").append(result.getExternalEntities().size()).append("\n");
        md.append("- Data Stores: ").append(result.getDataStores().size()).append("\n");
        md.append("- Data Flows: ").append(result.getDataFlows().size()).append("\n\n");
        
        // Data Structures
        md.append("## Data Structures\n\n");
        
        for (com.threatmodel.analyzer.model.DataStructure structure : result.getDataStructures()) {
            if (structure.isExternal()) {
                md.append("### ").append(structure.getName()).append(" [EXTERNAL]\n\n");
            } else {
                md.append("### ").append(structure.getName()).append("\n\n");
            }
            
            md.append("- **Type**: ").append(structure.getType()).append("\n");
            if (structure.getDescription() != null && !structure.getDescription().isEmpty()) {
                md.append("- **Description**: ").append(structure.getDescription()).append("\n");
            }
            md.append("- **Source File**: ").append(structure.getSourceFilePath()).append("\n\n");
            
            md.append("#### Fields\n\n");
            if (structure.getFields().isEmpty()) {
                md.append("*No fields found*\n\n");
            } else {
                md.append("| Field | Type | Description |\n");
                md.append("|-------|------|-------------|\n");
                
                for (com.threatmodel.analyzer.model.DataField field : structure.getFields()) {
                    md.append("| ");
                    if (field.isSensitive()) {
                        md.append("**").append(field.getName()).append("** [SENSITIVE]");
                    } else {
                        md.append(field.getName());
                    }
                    md.append(" | ").append(field.getType());
                    if (field.isCollection()) {
                        md.append(" [Collection]");
                    }
                    md.append(" | ");
                    if (field.getDescription() != null && !field.getDescription().isEmpty()) {
                        md.append(field.getDescription());
                    }
                    md.append(" |\n");
                }
                md.append("\n");
            }
        }
        
        // External Entities
        md.append("## External Entities\n\n");
        
        if (result.getExternalEntities().isEmpty()) {
            md.append("*No external entities found*\n\n");
        } else {
            md.append("| Name | Type | Description | Protocols |\n");
            md.append("|------|------|-------------|------------|\n");
            
            for (com.threatmodel.analyzer.model.ExternalEntity entity : result.getExternalEntities()) {
                md.append("| ").append(entity.getName());
                md.append(" | ").append(entity.getType());
                md.append(" | ");
                if (entity.getDescription() != null && !entity.getDescription().isEmpty()) {
                    md.append(entity.getDescription());
                }
                md.append(" | ");
                if (!entity.getProtocols().isEmpty()) {
                    md.append(String.join(", ", entity.getProtocols()));
                }
                md.append(" |\n");
            }
            md.append("\n");
        }
        
        // Processes
        md.append("## Processes\n\n");
        
        for (com.threatmodel.analyzer.model.Process process : result.getProcesses()) {
            md.append("### ").append(process.getName()).append("\n\n");
            
            if (process.getDescription() != null && !process.getDescription().isEmpty()) {
                md.append("- **Description**: ").append(process.getDescription()).append("\n");
            }
            md.append("- **Source File**: ").append(process.getSourceFilePath()).append("\n\n");
            
            md.append("#### Inputs\n\n");
            if (process.getInputDataStructureIds().isEmpty()) {
                md.append("*No input data structures found*\n\n");
            } else {
                for (String inputId : process.getInputDataStructureIds()) {
                    md.append("- ").append(inputId).append("\n");
                }
                md.append("\n");
            }
            
            md.append("#### Outputs\n\n");
            if (process.getOutputDataStructureIds().isEmpty()) {
                md.append("*No output data structures found*\n\n");
            } else {
                for (String outputId : process.getOutputDataStructureIds()) {
                    md.append("- ").append(outputId).append("\n");
                }
                md.append("\n");
            }
        }
        
        // Data Stores
        md.append("## Data Stores\n\n");
        
        if (result.getDataStores().isEmpty()) {
            md.append("*No data stores found*\n\n");
        } else {
            for (com.threatmodel.analyzer.model.DataStore store : result.getDataStores()) {
                md.append("### ").append(store.getName()).append("\n\n");
                
                md.append("- **Type**: ").append(store.getType()).append("\n");
                if (store.getDescription() != null && !store.getDescription().isEmpty()) {
                    md.append("- **Description**: ").append(store.getDescription()).append("\n");
                }
                md.append("\n");
                
                md.append("#### Stored Data Structures\n\n");
                if (store.getDataStructureIds().isEmpty()) {
                    md.append("*No data structures found*\n\n");
                } else {
                    for (String structureId : store.getDataStructureIds()) {
                        md.append("- ").append(structureId).append("\n");
                    }
                    md.append("\n");
                }
            }
        }
        
        // Data Flows
        md.append("## Data Flows\n\n");
        
        if (result.getDataFlows().isEmpty()) {
            md.append("*No data flows found*\n\n");
        } else {
            md.append("| Source | Destination | Data Structure | Type | Protocol | Description |\n");
            md.append("|--------|-------------|----------------|------|----------|-------------|\n");
            
            for (com.threatmodel.analyzer.model.DataFlow flow : result.getDataFlows()) {
                md.append("| ").append(flow.getSourceId());
                md.append(" | ").append(flow.getDestinationId());
                md.append(" | ").append(flow.getDataStructureId());
                md.append(" | ").append(flow.getType());
                md.append(" | ");
                if (flow.getProtocol() != null && !flow.getProtocol().isEmpty()) {
                    md.append(flow.getProtocol());
                }
                md.append(" | ");
                if (flow.getDescription() != null && !flow.getDescription().isEmpty()) {
                    md.append(flow.getDescription());
                }
                md.append(" |\n");
            }
            md.append("\n");
        }
        
        Files.writeString(markdownFile, md.toString());
        
        logger.info("Markdown output written to: {}", markdownFile);
    }
    
    /**
     * Escapes a string for CSV output
     */
    private String escapeCsv(String s) {
        if (s == null) {
            return "";
        }
        
        // If the string contains a comma, a double quote, or a newline, wrap it in quotes and escape any quotes
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        
        return s;
    }
}
