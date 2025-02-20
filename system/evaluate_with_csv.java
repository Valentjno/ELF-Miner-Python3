import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import weka.classifiers.trees.RandomForest;
import weka.classifiers.trees.J48;
import weka.classifiers.rules.PART;
import weka.classifiers.rules.JRip;
import weka.core.*;
import weka.core.SerializationHelper;

public class EnsemblePrediction {
    public static void main(String args[]) throws Exception {
        // Load models
        RandomForest rf = (RandomForest) SerializationHelper.read("../models/models/Random_Forest.model");
        J48 j48 = (J48) SerializationHelper.read("../models/models/J48.model");
        PART prt = (PART) SerializationHelper.read("../models/models/PART.model");
        JRip jrip = (JRip) SerializationHelper.read("../models/models/JRip.model");
        
        // Load headers from all.txt
        BufferedReader in = new BufferedReader(new FileReader("../arff_headers/all.txt"));
        String str;

        List<String> header_list = new ArrayList<>();
        while ((str = in.readLine()) != null) {
            header_list.add(str);
        }
        in.close();
        
        List<Integer> linenos = new ArrayList<>();
        for (int i = 3; i <= 149; i++) {
            linenos.add(i);
        }
        
        // Modify headers of arff file
        Path path = Paths.get("final.arff");
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        for (int i = 0; i < linenos.size(); i++) {
            lines.set(linenos.get(i) - 1, header_list.get(i));
        }
        Files.write(path, lines, StandardCharsets.UTF_8);
        
        // Load test set
        Instances testingdata = getDataFromFile("final.arff");
        int s = testingdata.numInstances();

        // Prepare CSV output
        FileWriter csvWriter = new FileWriter("predictions.csv");
        csvWriter.append("Instance,J48,PART,RandomForest,JRip,Ensemble\n");
        
        for (int i = 0; i < s; i++) {
            // Make predictions
            double valuej48 = j48.classifyInstance(testingdata.instance(i));
            double valuepart = prt.classifyInstance(testingdata.instance(i));
            double valuerf = rf.classifyInstance(testingdata.instance(i));
            double valuejrip = jrip.classifyInstance(testingdata.instance(i));
            double final_val = (valuej48 + valuepart + valuerf + valuejrip) / 4;
            
            // Get the name of the class value
            String predictionJ48 = testingdata.classAttribute().value((int) Math.round(valuej48));
            String predictionPART = testingdata.classAttribute().value((int) Math.round(valuepart));
            String predictionRF = testingdata.classAttribute().value((int) Math.round(valuerf));
            String predictionJRip = testingdata.classAttribute().value((int) Math.round(valuejrip));
            String predictionEnsemble = testingdata.classAttribute().value((int) Math.round(final_val));
            
            // Write to CSV
            csvWriter.append(i + "," + predictionJ48 + "," + predictionPART + "," + predictionRF + "," + predictionJRip + "," + predictionEnsemble + "\n");
        }
        
        csvWriter.flush();
        csvWriter.close();
        System.out.println("Predictions saved to predictions.csv");
    }
    
    private static Instances getDataFromFile(String filename) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        Instances data = new Instances(reader);
        reader.close();
        data.setClassIndex(data.numAttributes() - 1);
        return data;
    }
}
