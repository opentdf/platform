-- Insert test data for Entity Resolution Service SQL provider testing
-- Consistent with test data used in contract tests

-- Insert test users (consistent with contract test framework)
INSERT INTO ers_users (username, email, first_name, last_name, department, job_title, active) VALUES
    ('alice', 'alice@opentdf.test', 'Alice', 'Johnson', 'Engineering', 'Software Engineer', true),
    ('bob', 'bob@opentdf.test', 'Bob', 'Smith', 'Marketing', 'Product Manager', true),
    ('charlie', 'charlie@opentdf.test', 'Charlie', 'Brown', 'Security', 'Security Analyst', true),
    ('diana', 'diana@opentdf.test', 'Diana', 'Williams', 'Engineering', 'Senior Developer', true),
    ('eve', 'eve@opentdf.test', 'Eve', 'Davis', 'Operations', 'DevOps Engineer', true),
    ('frank', 'frank@opentdf.test', 'Frank', 'Miller', 'Sales', 'Sales Representative', false), -- inactive user
    ('grace', 'grace@opentdf.test', 'Grace', 'Wilson', 'HR', 'HR Specialist', true),
    ('henry', 'henry@opentdf.test', 'Henry', 'Taylor', 'Finance', 'Financial Analyst', true)
ON CONFLICT (username) DO NOTHING;

-- Insert test clients (consistent with contract test framework)
INSERT INTO ers_clients (client_id, client_name, description, environment, active) VALUES
    ('test-client-1', 'Test Client Application 1', 'Primary test client for integration testing', 'development', true),
    ('test-client-2', 'Test Client Application 2', 'Secondary test client for multi-client scenarios', 'development', true),
    ('opentdf-sdk', 'OpenTDF SDK', 'Official OpenTDF SDK client', 'production', true),
    ('external-client', 'External Integration Client', 'Third-party client application', 'staging', true),
    ('mobile-app', 'Mobile Application Client', 'Mobile app client for testing', 'development', true),
    ('web-portal', 'Web Portal Client', 'Web-based client application', 'production', true),
    ('legacy-system', 'Legacy System Integration', 'Legacy system client (inactive)', 'production', false), -- inactive client
    ('test-service', 'Test Service Client', 'Service-to-service client for testing', 'development', true)
ON CONFLICT (client_id) DO NOTHING;

-- Insert organizational groups
INSERT INTO ers_groups (group_name, group_type, description, parent_group_id, active) VALUES
    ('engineering', 'department', 'Engineering Department', NULL, true),
    ('marketing', 'department', 'Marketing Department', NULL, true),
    ('security', 'department', 'Security Department', NULL, true),
    ('operations', 'department', 'Operations Department', NULL, true),
    ('frontend-team', 'team', 'Frontend Development Team', 1, true), -- child of engineering
    ('backend-team', 'team', 'Backend Development Team', 1, true),   -- child of engineering
    ('devops-team', 'team', 'DevOps Team', 4, true),               -- child of operations
    ('executives', 'role', 'Executive Leadership', NULL, true),
    ('contractors', 'role', 'External Contractors', NULL, true),
    ('qa-team', 'team', 'Quality Assurance Team', 1, true)         -- child of engineering
ON CONFLICT (group_name) DO NOTHING;

-- Insert user-group memberships
INSERT INTO ers_user_groups (user_id, group_id, role) VALUES
    -- Alice: Engineering (Frontend Team)
    ((SELECT id FROM ers_users WHERE username = 'alice'), (SELECT id FROM ers_groups WHERE group_name = 'engineering'), 'member'),
    ((SELECT id FROM ers_users WHERE username = 'alice'), (SELECT id FROM ers_groups WHERE group_name = 'frontend-team'), 'lead'),
    
    -- Bob: Marketing
    ((SELECT id FROM ers_users WHERE username = 'bob'), (SELECT id FROM ers_groups WHERE group_name = 'marketing'), 'member'),
    
    -- Charlie: Security
    ((SELECT id FROM ers_users WHERE username = 'charlie'), (SELECT id FROM ers_groups WHERE group_name = 'security'), 'member'),
    ((SELECT id FROM ers_users WHERE username = 'charlie'), (SELECT id FROM ers_groups WHERE group_name = 'executives'), 'member'),
    
    -- Diana: Engineering (Backend Team)
    ((SELECT id FROM ers_users WHERE username = 'diana'), (SELECT id FROM ers_groups WHERE group_name = 'engineering'), 'member'),
    ((SELECT id FROM ers_users WHERE username = 'diana'), (SELECT id FROM ers_groups WHERE group_name = 'backend-team'), 'senior'),
    
    -- Eve: Operations (DevOps Team)
    ((SELECT id FROM ers_users WHERE username = 'eve'), (SELECT id FROM ers_groups WHERE group_name = 'operations'), 'member'),
    ((SELECT id FROM ers_users WHERE username = 'eve'), (SELECT id FROM ers_groups WHERE group_name = 'devops-team'), 'member'),
    
    -- Grace: HR (Executives)
    ((SELECT id FROM ers_users WHERE username = 'grace'), (SELECT id FROM ers_groups WHERE group_name = 'executives'), 'member'),
    
    -- Henry: Finance
    ((SELECT id FROM ers_users WHERE username = 'henry'), (SELECT id FROM ers_groups WHERE group_name = 'executives'), 'member')
ON CONFLICT (user_id, group_id) DO NOTHING;

-- Insert client permissions for complex authorization scenarios
INSERT INTO ers_client_permissions (client_id, permission_name, resource_type, granted_at) VALUES
    -- test-client-1 permissions
    ((SELECT id FROM ers_clients WHERE client_id = 'test-client-1'), 'tdf.read', 'data', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'test-client-1'), 'tdf.write', 'data', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'test-client-1'), 'policy.read', 'policy', CURRENT_TIMESTAMP),
    
    -- test-client-2 permissions (limited)
    ((SELECT id FROM ers_clients WHERE client_id = 'test-client-2'), 'tdf.read', 'data', CURRENT_TIMESTAMP),
    
    -- opentdf-sdk permissions (full access)
    ((SELECT id FROM ers_clients WHERE client_id = 'opentdf-sdk'), 'tdf.read', 'data', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'opentdf-sdk'), 'tdf.write', 'data', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'opentdf-sdk'), 'policy.read', 'policy', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'opentdf-sdk'), 'policy.write', 'policy', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'opentdf-sdk'), 'admin.manage', 'system', CURRENT_TIMESTAMP),
    
    -- external-client permissions (restricted)
    ((SELECT id FROM ers_clients WHERE client_id = 'external-client'), 'tdf.read', 'data', CURRENT_TIMESTAMP),
    
    -- mobile-app permissions
    ((SELECT id FROM ers_clients WHERE client_id = 'mobile-app'), 'tdf.read', 'data', CURRENT_TIMESTAMP),
    ((SELECT id FROM ers_clients WHERE client_id = 'mobile-app'), 'tdf.write', 'data', CURRENT_TIMESTAMP)
ON CONFLICT (client_id, permission_name, resource_type) DO NOTHING;

-- Verify data insertion
SELECT 'Users inserted: ' || COUNT(*) FROM ers_users;
SELECT 'Clients inserted: ' || COUNT(*) FROM ers_clients;
SELECT 'Groups inserted: ' || COUNT(*) FROM ers_groups;
SELECT 'User-Group memberships: ' || COUNT(*) FROM ers_user_groups;
SELECT 'Client permissions: ' || COUNT(*) FROM ers_client_permissions;