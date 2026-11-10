-- Entity Resolution Service Test Database Schema
-- Creates tables for SQL provider testing with sample user/entity data

-- Users table for entity resolution
CREATE TABLE IF NOT EXISTS ers_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    department VARCHAR(255),
    job_title VARCHAR(255),
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clients table for environment entity resolution
CREATE TABLE IF NOT EXISTS ers_clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    description TEXT,
    environment VARCHAR(100) DEFAULT 'development',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Groups table for organizational structure
CREATE TABLE IF NOT EXISTS ers_groups (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(255) UNIQUE NOT NULL,
    group_type VARCHAR(100) DEFAULT 'department',
    description TEXT,
    parent_group_id INTEGER REFERENCES ers_groups(id),
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User-Group memberships for complex queries
CREATE TABLE IF NOT EXISTS ers_user_groups (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES ers_users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES ers_groups(id) ON DELETE CASCADE,
    role VARCHAR(100) DEFAULT 'member',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, group_id)
);

-- Client permissions for complex authorization scenarios
CREATE TABLE IF NOT EXISTS ers_client_permissions (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES ers_clients(id) ON DELETE CASCADE,
    permission_name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(client_id, permission_name, resource_type)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_ers_users_username ON ers_users(username);
CREATE INDEX IF NOT EXISTS idx_ers_users_email ON ers_users(email);
CREATE INDEX IF NOT EXISTS idx_ers_users_active ON ers_users(active);
CREATE INDEX IF NOT EXISTS idx_ers_clients_client_id ON ers_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_ers_clients_active ON ers_clients(active);
CREATE INDEX IF NOT EXISTS idx_ers_groups_parent ON ers_groups(parent_group_id);
CREATE INDEX IF NOT EXISTS idx_ers_user_groups_user ON ers_user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_ers_user_groups_group ON ers_user_groups(group_id);

-- Comments for documentation
COMMENT ON TABLE ers_users IS 'User entities for multi-strategy ERS testing';
COMMENT ON TABLE ers_clients IS 'Client/application entities for environment resolution';
COMMENT ON TABLE ers_groups IS 'Organizational groups for complex entity relationships';
COMMENT ON TABLE ers_user_groups IS 'Many-to-many relationship between users and groups';
COMMENT ON TABLE ers_client_permissions IS 'Client-specific permissions for authorization testing';