import { getClient } from './keycloakData.js';
import http from 'k6/http';
import { check, sleep } from 'k6';

export default function() {
  // Get total VUs from environment variable or use a default value
  const totalVUs = __ENV.TOTAL_VUS ? parseInt(__ENV.TOTAL_VUS) : 1000;

  // Calculate padding digits based on total VUs
  const paddingDigits = totalVUs > 1 ? Math.floor(Math.log10(totalVUs - 1)) + 1 : 1;

  // Calculate client index (0-based) from VU number (1-based)
  const clientIndex = (__VU - 1) % totalVUs;

  // Format client ID with appropriate padding
  const paddedIndex = String(clientIndex).padStart(paddingDigits, '0');
  const clientId = `opentdf-${paddedIndex}`;

  // Get the client from keycloakData
  const client = getClient(clientId);

  if (__VU <= 10) {
    console.log(`VU ${__VU} using client ${clientId} ${client.clientId}`);
  }

  // Get URLs from environment variables or use defaults
  const keycloakBaseUrl = __ENV.KEYCLOAK_URL || 'http://localhost:8888';
  const authServiceBaseUrl = __ENV.API_URL || 'http://localhost:8080';
  const realmName = __ENV.REALM || 'opentdf';

  // Step 1: Get token endpoint from environment or discover it
  let tokenEndpoint;

  if (__ENV.AUTH_URL) {
    // Use the provided auth URL directly
    tokenEndpoint = __ENV.AUTH_URL;
    if (__VU === 1) {
      console.log(`Using AUTH_URL from environment: ${tokenEndpoint}`);
    }
  } else if (__VU === 1 || !__ENV.tokenEndpoint) {
    // Discover the token endpoint if not provided and not already discovered
    const realmInfoUrl = `${keycloakBaseUrl}/auth/realms/${realmName}`;

    const realmInfoResponse = http.get(realmInfoUrl);

    check(realmInfoResponse, {
      'Realm info retrieved': (r) => r.status === 200,
      'Token service URL available': (r) => r.json('token-service') !== undefined,
    });

    if (realmInfoResponse.status !== 200) {
      console.error(`Failed to get realm info: ${realmInfoResponse.status}`);
      return;
    }

    const realmInfo = JSON.parse(realmInfoResponse.body);
    tokenEndpoint = `${realmInfo['token-service']}/token`;
    __ENV.tokenEndpoint = tokenEndpoint;

    console.log(`Using discovered token endpoint: ${tokenEndpoint}`);
  } else {
    // Use the previously discovered endpoint
    tokenEndpoint = __ENV.tokenEndpoint;
  }

  // Step 2: Get access token using client credentials
  const tokenData = {
    'client_id': client.clientId,
    'client_secret': client.secret,
    'grant_type': 'client_credentials'
  };

  const tokenHeaders = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const tokenResponse = http.post(tokenEndpoint, tokenData, { headers: tokenHeaders });

  check(tokenResponse, {
    'Token request successful': (r) => r.status === 200,
    'Access token received': (r) => r.json('access_token') !== undefined,
  });

  if (tokenResponse.status !== 200 || !tokenResponse.json('access_token')) {
    console.error(`Client credentials grant failed for ${client.clientId}: ${tokenResponse.status} ${tokenResponse.body}`);
    return;
  }

  const token = tokenResponse.json('access_token');

  if (__VU <= 5) {
    console.log(`Successfully obtained access token for ${client.clientId}`);
  }

  // Step 3: Test the authorization service endpoints
  const authHeaders = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  // Test each endpoint in the OpenTDF Authorization Service

  // 1. Test /v1/entitlements endpoint
  const entitlementsUrl = `${authServiceBaseUrl}/v1/entitlements`;
  const entitlementsPayload = JSON.stringify({
    "entities": [
      {
        "id": "e1",
        "emailAddress": "sample-user@sample.com"
      }
    ],
    "scope": {
      "attributeValueFqns": [
        "https://example.net/attr/Classification/value/Unclassified"
      ]
    }
  });

  const entitlementsResponse = http.post(
    entitlementsUrl,
    entitlementsPayload,
    { headers: authHeaders }
  );

  check(entitlementsResponse, {
    'Entitlements endpoint returns 200': (r) => r.status === 200,
    'Entitlements response has entitlements array': (r) => r.json('entitlements') !== undefined,
  });

  if (__VU <= 5) {
    console.log(`Entitlements response: ${entitlementsResponse.status}`);
  }

  // 2. Test /v1/authorization endpoint
  const authorizationUrl = `${authServiceBaseUrl}/v1/authorization`;
  const authorizationPayload = JSON.stringify({
    "decisionRequests": [
      {
        "actions": [
          {
            "name": "read"
          }
        ],
        "entityChains": [
          {
            "id": "ec1",
            "entities": [
              {
                "emailAddress": "sample-user@sample.com"
              }
            ]
          }
        ],
        "resourceAttributes": [
          {
            "resourceAttributesId": "attr-set-1",
            "attributeValueFqns": [
              "https://example.net/attr/Classification/value/Unclassified"
            ]
          }
        ]
      }
    ]
  });

  const authorizationResponse = http.post(
    authorizationUrl,
    authorizationPayload,
    { headers: authHeaders }
  );

  check(authorizationResponse, {
    'Authorization endpoint returns 200': (r) => r.status === 200,
    'Authorization response has decisionResponses': (r) => r.json('decisionResponses') !== undefined,
  });

  if (__VU <= 5) {
    console.log(`Authorization response: ${authorizationResponse.status}`);

    // If there was an error, log it for debugging
    if (authorizationResponse.status !== 200) {
      console.log(`Authorization error: ${authorizationResponse.body}`);
    }
  }

  // Add small sleep to avoid overwhelming the service
  sleep(0.5);
}

export function handleSummary(data) {
  // Calculate success rates for all endpoints
  const tokenSuccess = data.metrics.checks.values['Token request successful'] || { passes: 0, fails: 0 };
  const entitlementsSuccess = data.metrics.checks.values['Entitlements endpoint returns 200'] || { passes: 0, fails: 0 };
  const authorizationSuccess = data.metrics.checks.values['Authorization endpoint returns 200'] || { passes: 0, fails: 0 };

  const tokenSuccessRate = (tokenSuccess.passes / (tokenSuccess.passes + tokenSuccess.fails)) * 100 || 0;
  const entitlementsSuccessRate = (entitlementsSuccess.passes / (entitlementsSuccess.passes + entitlementsSuccess.fails)) * 100 || 0;
  const authorizationSuccessRate = (authorizationSuccess.passes / (authorizationSuccess.passes + authorizationSuccess.fails)) * 100 || 0;

  // Calculate throughput (requests per second) for each endpoint
  const testDuration = (data.state.testStop - data.state.testStart) / 1000; // in seconds

  // Calculate requests per endpoint (estimated based on successful checks)
  const entitlementsCount = entitlementsSuccess.passes || 0;
  const authorizationCount = authorizationSuccess.passes || 0;

  // Calculate throughput
  const entitlementsThroughput = entitlementsCount / testDuration;
  const authorizationThroughput = authorizationCount / testDuration;

  // Target throughput requirements
  const targetThroughput = 5000; // requests/sec

  // Determine if targets were met
  const entitlementsTargetMet = entitlementsThroughput >= targetThroughput;
  const authorizationTargetMet = authorizationThroughput >= targetThroughput;

  // Get service URLs for reporting
  const authUrl = __ENV.AUTH_URL || __ENV.tokenEndpoint || "default Keycloak URL";
  const apiUrl = __ENV.API_URL || "http://localhost:8080";

  return {
    'stdout': `
      OpenTDF Authorization Service Test Summary
      ------------------------------------------
      
      THROUGHPUT REQUIREMENTS:
      ✓ /v1/entitlements: ${entitlementsThroughput.toFixed(2)} req/sec [${entitlementsTargetMet ? 'PASS' : 'FAIL'}] (Target: ${targetThroughput} req/sec)
      ✓ /v1/authorization: ${authorizationThroughput.toFixed(2)} req/sec [${authorizationTargetMet ? 'PASS' : 'FAIL'}] (Target: ${targetThroughput} req/sec)
      
      ENDPOINT PERFORMANCE:
      - /v1/entitlements response time: Avg ${(data.metrics.http_req_duration.values.avg || 0).toFixed(2)}ms, P95 ${(data.metrics.http_req_duration.values['p(95)'] || 0).toFixed(2)}ms
      - /v1/authorization response time: Avg ${(data.metrics.http_req_duration.values.avg || 0).toFixed(2)}ms, P95 ${(data.metrics.http_req_duration.values['p(95)'] || 0).toFixed(2)}ms
      
      SUCCESS RATES:
      - Authentication: ${tokenSuccessRate.toFixed(2)}% (${tokenSuccess.passes} of ${tokenSuccess.passes + tokenSuccess.fails} requests)
      - /v1/entitlements: ${entitlementsSuccessRate.toFixed(2)}% (${entitlementsSuccess.passes} of ${entitlementsSuccess.passes + entitlementsSuccess.fails} requests)
      - /v1/authorization: ${authorizationSuccessRate.toFixed(2)}% (${authorizationSuccess.passes} of ${authorizationSuccess.passes + authorizationSuccess.fails} requests)
      
      TEST CONFIGURATION:
      - Auth URL: ${authUrl}
      - API URL: ${apiUrl}
      - Virtual Users: ${__ENV.TOTAL_VUS || 0}
      - Test Duration: ${testDuration.toFixed(2)} seconds
      - Total Requests: ${data.metrics.http_reqs.values.count || 0}
      
      SUMMARY:
      The system ${(entitlementsTargetMet && authorizationTargetMet) ? 'MEETS' : 'DOES NOT MEET'} the throughput requirements:
      - /entitlements: 5000 requests/sec
      - /decisions: 5000 requests/sec
    `,
  };
}
