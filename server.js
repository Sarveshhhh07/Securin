const express = require('express');
const mysql = require('mysql');
const path = require('path');
const app = express();
const cors = require('cors')

var cveId = '';
app.use(cors())
const port = 3000;

// MySQL database connection configuration
const connection = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: 'root',
    database: 'CVE_DB' // Your database name
});

// Connect to MySQL database
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

app.get('/', (req, res) => {
    console.log(path.join(__dirname, 'home.html'));
    res.sendFile(path.join(__dirname, 'home.html'));
});

// API endpoint to fetch CVE data
app.get('/cve', (req, res) => {
    const page = parseInt(req.query.page) || 1; // Get the requested page from the query parameter, or default to 1
    const limit = parseInt(req.query.limit) || 10; // Get the requested results per page from the query parameter, or default to 10
    const offset = (page - 1) * limit; // Calculate the offset based on the requested page and limit

    //const query = 'SELECT CVE_ID, IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, STATUS, ACCESS_VECTOR, ACCESS_COMPLEXITY, AUTHENTICATION, CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, CRITERIA, MATCH_CRITERIA_ID, VULNERABLE FROM CVE_List LIMIT ? OFFSET ?';
    const query = 'SELECT CVE_ID, IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, STATUS FROM CVE_List LIMIT ? OFFSET ?';
    const values = [limit, offset];

    console.log('Executing MySQL query:', query, values);

    connection.query(query, values, (err, results) => {
        if (err) {
            console.error('Error executing MySQL query:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        // Print fetched data to console
        console.log('Fetched data:', results);

        // Convert the results to the expected format
        const formattedResults = results.map(row => ({
            CVE_ID: row.CVE_ID,
            IDENTIFIER: row.IDENTIFIER,
            PUBLISHED_DATE: row.PUBLISHED_DATE,
            LAST_MODIFIED_DATE: row.LAST_MODIFIED_DATE,
            STATUS: row.STATUS,
            ACCESS_VECTOR: row.ACCESS_VECTOR,
            ACCESS_COMPLEXITY: row.ACCESS_COMPLEXITY,
            AUTHENTICATION: row.AUTHENTICATION,
            CONFIDENTIALITY_IMPACT: row.CONFIDENTIALITY_IMPACT,
            INTEGRITY_IMPACT: row.INTEGRITY_IMPACT,
            AVAILABILITY_IMPACT: row.AVAILABILITY_IMPACT,
            CRITERIA: row.CRITERIA,
            MATCH_CRITERIA_ID: row.MATCH_CRITERIA_ID,
            VULNERABLE: row.VULNERABLE
        }));

        res.json(formattedResults);
    });
});


// API endpoint to fetch CVE details for a specific CVE ID
app.get('/cve-details/:cveId', (req, res) => {
    cveId = req.params.cveId; // Extract CVE ID from request parameters
    res.sendFile(path.join(__dirname, 'cve_details.html'));
    // Query to fetch CVE details for the specified CVE I
});

app.get('/get-details', (req, res) => {
    const query = 'SELECT CVE_ID, VECTOR_STRING, ACCESS_VECTOR, ACCESS_COMPLEXITY, DESCRIPTION, AUTHENTICATION, CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, CRITERIA, MATCH_CRITERIA_ID, VULNERABLE, SCORE, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE FROM CVE_List WHERE CVE_ID = ?';
    const values = [cveId];

    console.log('Executing MySQL query:', query, values);

    connection.query(query, values, (err, results) => {
        if (err) {
            console.error('Error executing MySQL query:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        // Check if any results were found for the specified CVE ID
        if (results.length === 0) {
            res.status(404).json({ error: 'CVE not found' });
            return;
        }
        console.log(results);

        // Format the fetched data
        const formattedResult = {
            cveId: results[0].CVE_ID,
            description: results[0].DESCRIPTION,
            cvssMetrics: {
                vectorString: results[0].VECTOR_STRING,
                severity: results[0].BASE_SEVERITY,
                score: results[0].SCORE,
                // vectorString: results[0].CVSS_VECTOR_STRING,
                exploitabilityScore: results[0].EXPLOITABILITY_SCORE,
                impactScore: results[0].IMPACT_SCORE
            },
            cpeList: [
                {
                    cpe: results[0].CRITERIA,
                    criteria: results[0].CRITERIA,
                    matchCriteriaId: results[0].MATCH_CRITERIA_ID,
                    vulnerable: results[0].VULNERABLE
                }
                // You can add more CPEs here as needed
            ],
            cpeeMetrics: {
                accessVector: results[0].ACCESS_VECTOR,
                accessComplexity: results[0].ACCESS_COMPLEXITY,
                authentication: results[0].AUTHENTICATION,
                confidentialityImpact: results[0].CONFIDENTIALITY_IMPACT,
                integrityImpact: results[0].INTEGRITY_IMPACT,
                availabilityImpact: results[0].AVAILABILITY_IMPACT
            }
            // You can add more fields here as needed
        };

        res.json(formattedResult);
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
