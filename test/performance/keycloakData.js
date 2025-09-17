// Auto-generated keycloakData.js file for k6 testing
// Provides getUser() and getClient() functions based on k6 VU ID

// Regular user templates
const regularUsers = [
  {baseName:"sample-user", password:"testuser123", realm:"opentdf", copies:10}
];

// Service account templates
const serviceAccounts = [
  {baseName:"opentdf", password:"secret", realm:"opentdf", copies:10},
  {baseName:"opentdf-sdk", password:"secret", realm:"opentdf", copies:1},
  {baseName:"tdf-entity-resolution", password:"secret", realm:"opentdf", copies:1},
  {baseName:"tdf-authorization-svc", password:"secret", realm:"opentdf", copies:1}
];

// Client information
const clients = [
  {clientId:"opentdf", secret:"secret", type:"service", realm:"opentdf"},
  {clientId:"opentdf-sdk", secret:"secret", type:"service", realm:"opentdf"},
  {clientId:"tdf-entity-resolution", secret:"secret", type:"service", realm:"opentdf"},
  {clientId:"tdf-authorization-svc", secret:"secret", type:"service", realm:"opentdf"},
  {clientId:"opentdf-public", secret:"", type:"public", realm:"opentdf"}
];

/**
 * Get a user based on the current k6 VU ID.
 * @returns {Object} User credentials object with username and password
 */
export function getUser() {
  // Get current VU ID (or use 1 if not in k6 context)
  const vuId = typeof __VU !== 'undefined' ? __VU : 1;

  // Combine regular users and service accounts
  const allUserTemplates = [...regularUsers, ...serviceAccounts];

  // Calculate total available users
  const totalUsers = allUserTemplates.reduce((sum, t) => sum + (t.copies || 1), 0);

  // Map VU ID to user index (with wrapping for large VU counts)
  const targetIndex = (vuId - 1) % totalUsers;

  // Find the right template and copy number
  let currentIndex = 0;
  for (const template of allUserTemplates) {
    const templateCount = template.copies || 1;

    if (currentIndex + templateCount > targetIndex) {
      // We found the right template, now calculate which copy
      const copyIndex = targetIndex - currentIndex;

      // Format username based on template type and copy index
      let username = template.baseName;
      const isServiceAccount = serviceAccounts.includes(template);

      if (isServiceAccount) {
        username = "service-account-" + template.baseName;
      }

      if (template.copies > 1) {
        username += "-" + (copyIndex + 1);
      }

      return {
        username: username,
        password: template.password,
        realm: template.realm,
        isServiceAccount: isServiceAccount
      };
    }

    currentIndex += templateCount;
  }

  // Fallback user (should never reach here if totalUsers calculation is correct)
  return {
    username: "fallback-user",
    password: "fallback-password"
  };
}

/**
 * Get a client based on the k6 VU ID or client name.
 * @param {string} [clientId] - Optional client name to retrieve, defaults to primary client
 * @returns {Object} Client information object
 */
export function getClient(clientId) {
  if (clientId) {
    // Find by client name
    const client = clients.find(c => c.clientId === clientId);
    if (client) return client;
  }

  // Default to primary client or first in list
  const primaryClient = clients.find(c => c.clientId === "opentdf");
  if (primaryClient) return primaryClient;

  return clients[0] || { clientId: "opentdf", secret: "secret" };
}

// Export additional utilities
export const getAllUsers = () => [...regularUsers, ...serviceAccounts];
export const getRegularUsers = () => regularUsers;
export const getServiceAccounts = () => serviceAccounts;
export const getClients = () => clients;
